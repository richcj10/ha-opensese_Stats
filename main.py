"""OPNsense Stats.

Polls an OPNsense firewall's API and publishes live throughput, top talkers, DNS (Unbound) statistics,
gateway quality and packet-filter state to Home Assistant via MQTT discovery.

Fast loop (poll_interval): interface counters -> Mbit/s, gateways, pf states, top talkers.
Slow loop (slow_interval): Unbound stats + top domains + top DNS clients, DHCP leases (host names), system.
"""
import base64
import json
import logging
import os
import ssl
import time
import urllib.request
from typing import Any, Dict, List, Optional

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("opnsense_stats")

OPTIONS_PATH = "/data/options.json"
BASE = "opnsense_stats"
MODEL = "OPNsense Stats"
TOP_N = 8

MBPS = {"unit_of_measurement": "Mbit/s", "state_class": "measurement", "device_class": "data_rate"}
# (component, object_id, name, state key, extra discovery fields); None in json_attributes_topic = full state
ENTITIES = [
    ("sensor", "status", "Status", "status", {"icon": "mdi:wall-fire", "json_attributes_topic": None}),
    ("binary_sensor", "online", "API Online", "online",
     {"payload_on": "on", "payload_off": "off", "device_class": "connectivity", "entity_category": "diagnostic"}),
    ("sensor", "wan_down", "WAN Download", "wan.rx_mbps", dict(MBPS, icon="mdi:download-network")),
    ("sensor", "wan_up", "WAN Upload", "wan.tx_mbps", dict(MBPS, icon="mdi:upload-network")),
    ("sensor", "lan_in", "LAN In", "lan.rx_mbps", dict(MBPS, icon="mdi:download-network-outline")),
    ("sensor", "lan_out", "LAN Out", "lan.tx_mbps", dict(MBPS, icon="mdi:upload-network-outline")),
    ("sensor", "wan_latency", "WAN Latency", "gw_wan.delay_ms",
     {"unit_of_measurement": "ms", "state_class": "measurement", "icon": "mdi:timer-sand"}),
    ("sensor", "wan_jitter", "WAN Jitter", "gw_wan.stddev_ms",
     {"unit_of_measurement": "ms", "state_class": "measurement", "icon": "mdi:sine-wave"}),
    ("sensor", "wan_loss", "WAN Packet Loss", "gw_wan.loss_pct",
     {"unit_of_measurement": "%", "state_class": "measurement", "icon": "mdi:lan-disconnect"}),
    ("sensor", "pf_states", "Firewall States", "pf.states",
     {"state_class": "measurement", "icon": "mdi:table-network"}),
    ("sensor", "pf_new_states", "New States per Second", "pf.inserts_ps",
     {"unit_of_measurement": "/s", "state_class": "measurement", "icon": "mdi:plus-network"}),
    ("sensor", "dns_qps", "DNS Queries per Second", "dns.qps",
     {"unit_of_measurement": "q/s", "state_class": "measurement", "icon": "mdi:dns"}),
    ("sensor", "dns_cache_hit", "DNS Cache Hit Rate", "dns.cache_hit_pct",
     {"unit_of_measurement": "%", "state_class": "measurement", "icon": "mdi:cached"}),
    ("sensor", "dns_recursion", "DNS Recursion Time", "dns.recursion_ms",
     {"unit_of_measurement": "ms", "state_class": "measurement", "icon": "mdi:timer-outline"}),
    ("sensor", "dns_queries_24h", "DNS Queries (24h)", "dns.queries_24h",
     {"state_class": "measurement", "icon": "mdi:counter"}),
    ("sensor", "top_talker", "Top Talker", "top_talker", {"icon": "mdi:account-network"}),
    ("sensor", "uptime", "Uptime", "sys.uptime", {"icon": "mdi:timer-outline", "entity_category": "diagnostic"}),
]


def load_options() -> dict:
    with open(OPTIONS_PATH) as f:
        return json.load(f)


def supervisor_token() -> str:
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
        try:
            with open(f"/run/s6/container_environment/{name}") as f:
                tok = f.read().strip()
                if tok:
                    return tok
        except OSError:
            pass
    return ""


def mqtt_settings(opts: dict) -> Optional[dict]:
    if opts.get("mqtt_host"):
        return dict(host=opts["mqtt_host"], port=int(opts.get("mqtt_port") or 1883),
                    username=opts.get("mqtt_user", ""), password=opts.get("mqtt_password", ""))
    tok = supervisor_token()
    if not tok:
        log.error("No Supervisor token; set mqtt_host/mqtt_user/mqtt_password in the add-on options")
        return None
    req = urllib.request.Request("http://supervisor/services/mqtt", headers={"Authorization": "Bearer " + tok})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.load(r)["data"]
    except Exception as e:
        log.error("Supervisor MQTT lookup failed (%s); set mqtt_host/mqtt_user/mqtt_password instead", e)
        return None
    log.info("MQTT settings from Supervisor: %s:%s user=%s", d["host"], d["port"], d.get("username"))
    return dict(host=d["host"], port=int(d["port"]), username=d.get("username", ""), password=d.get("password", ""))


# ---------------------------------------------------------------- OPNsense API
class Api:
    def __init__(self, host: str, key: str, secret: str, verify: bool):
        self.base = f"https://{host}/api/"
        self.auth = "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode()
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get(self, path: str, timeout: float = 15) -> Any:
        req = urllib.request.Request(self.base + path, headers={"Authorization": self.auth})
        with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
            return json.load(r)


def f(v: Any) -> Optional[float]:
    try:
        return float(str(v).replace("%", "").replace("ms", "").strip())
    except (TypeError, ValueError):
        return None


def r1(v: Optional[float], n: int = 1) -> Optional[float]:
    return None if v is None else round(v, n)


class Poller:
    def __init__(self, api: Api, opts: dict):
        self.api = api
        self.opts = opts
        self.prev_if: Dict[str, tuple] = {}     # interface -> (t, rx bytes, tx bytes)
        self.prev_pf: Optional[tuple] = None    # (t, inserts, matches)
        self.prev_dns: Optional[tuple] = None   # (t, queries)
        self.names: Dict[str, str] = {}         # ip -> host name (Kea leases)
        self.macs: Dict[str, str] = {}          # ip -> vendor
        self.slow: Dict[str, Any] = {}
        self.slow_at = 0.0

    def name(self, ip: str, rname: str = "") -> str:
        if ip in ("127.0.0.1", "::1"):
            return "firewall"
        n = (self.names.get(ip) or rname or "").rstrip(".")
        for dom in (self.opts.get("strip_domain") or "").split(","):
            dom = dom.strip()
            if dom and n.endswith("." + dom):
                n = n[: -len(dom) - 1]
        return n

    # -- fast data
    def interfaces(self, now: float) -> Dict[str, Any]:
        out = {}
        d = self.api.get("diagnostics/traffic/interface")["interfaces"]
        for key, i in d.items():
            rx, tx = int(i.get("bytes received") or 0), int(i.get("bytes transmitted") or 0)
            line = f((i.get("line rate") or "").split(" ")[0])
            e = dict(name=i.get("name") or key, device=i.get("device"), rx_bytes=rx, tx_bytes=tx,
                     line_mbps=r1(line / 1e6, 0) if line else None,
                     errors=int(i.get("input errors") or 0) + int(i.get("output errors") or 0),
                     drops=int(i.get("input queue drops") or 0) + int(i.get("send queue drops") or 0))
            p = self.prev_if.get(key)
            if p and now > p[0] and rx >= p[1] and tx >= p[2]:
                e["rx_mbps"] = r1((rx - p[1]) * 8 / (now - p[0]) / 1e6, 2)
                e["tx_mbps"] = r1((tx - p[2]) * 8 / (now - p[0]) / 1e6, 2)
            self.prev_if[key] = (now, rx, tx)
            out[key] = e
        return out

    def gateways(self) -> Dict[str, Any]:
        out = {}
        for g in self.api.get("routes/gateway/status").get("items", []):
            out[g["name"]] = dict(name=g["name"], address=g.get("address"), status=g.get("status_translated"),
                                  delay_ms=f(g.get("delay")), stddev_ms=f(g.get("stddev")), loss_pct=f(g.get("loss")),
                                  monitor=g.get("monitor"))
        return out

    def pf(self, now: float) -> Dict[str, Any]:
        info = self.api.get("diagnostics/firewall/pf_statistics/info")["info"]
        st = info.get("state-table", {})
        states = st.get("current-entries", {}).get("total")
        inserts = st.get("inserts", {}).get("total")
        matches = info.get("counters", {}).get("match", {}).get("total")
        out = dict(states=states, mismatch=info.get("counters", {}).get("state-mismatch", {}).get("total"))
        try:
            lim = self.api.get("diagnostics/firewall/pf_states?rowCount=1")
            out["limit"] = int(lim.get("limit"))
        except Exception:
            pass
        if self.prev_pf and now > self.prev_pf[0]:
            dt = now - self.prev_pf[0]
            out["inserts_ps"] = r1((inserts - self.prev_pf[1]) / dt)
            out["matches_ps"] = r1((matches - self.prev_pf[2]) / dt)
        self.prev_pf = (now, inserts, matches)
        return out

    def talkers(self) -> Dict[str, Any]:
        lan_if = self.opts.get("lan_interface", "lan")
        wan_if = self.opts.get("wan_interface", "wan")
        d = self.api.get(f"diagnostics/traffic/top/{lan_if},{wan_if}", timeout=25)

        def rows(recs, local):
            out = []
            for r in sorted(recs, key=lambda x: -(x.get("rate_bits") or 0)):
                ip = r.get("address") or ""
                if ip in ("0.0.0.0", "", "255.255.255.255"):
                    continue
                peers = [p.get("address") for p in (r.get("details") or [])]
                out.append(dict(ip=ip, name=self.name(ip, r.get("rname")) if local else (r.get("rname") or "").rstrip("."),
                                vendor=self.macs.get(ip) if local else None,
                                # pftop "in" = the listed address is the destination. LAN host: in = its
                                # download. WAN remote: out = it is sending to us = our download.
                                down_mbps=r1((r.get("rate_bits_in" if local else "rate_bits_out") or 0) / 1e6, 3),
                                up_mbps=r1((r.get("rate_bits_out" if local else "rate_bits_in") or 0) / 1e6, 3),
                                mbps=r1((r.get("rate_bits") or 0) / 1e6, 3),
                                bytes=r.get("cumulative_bytes"), peers=len(peers)))
                if len(out) >= TOP_N:
                    break
            return out
        return dict(lan=rows((d.get(lan_if) or {}).get("records", []), True),
                    wan=rows((d.get(wan_if) or {}).get("records", []), False))

    # -- slow data
    def slow_poll(self, now: float) -> None:
        s: Dict[str, Any] = {}
        names: Dict[str, str] = {}
        # weakest first: Unbound host overrides, then Kea reservations, then the names clients send in leases
        try:
            for x in self.api.get("unbound/settings/search_host_override?rowCount=-1").get("rows", []):
                if x.get("rr") == "A" and x.get("server") and x.get("hostname") and x.get("enabled", "1") == "1":
                    names[x["server"]] = x["hostname"]
        except Exception as e:
            log.debug("host overrides: %s", e)
        try:
            for x in self.api.get("kea/dhcpv4/search_reservation?rowCount=-1").get("rows", []):
                if x.get("ip_address") and x.get("hostname"):
                    names[x["ip_address"]] = x["hostname"]
        except Exception as e:
            log.debug("reservations: %s", e)
        try:
            leases = self.api.get("kea/leases4/search?rowCount=-1").get("rows", [])
            for x in leases:
                if x.get("address") and x.get("hostname"):
                    names[x["address"]] = x["hostname"]
            self.macs = {x["address"]: x.get("mac_info") or "" for x in leases if x.get("address")}
            s["leases"] = len(leases)
        except Exception as e:
            log.debug("leases: %s", e)
        self.names = names
        try:
            tot = self.api.get("unbound/diagnostics/stats")["data"]["total"]
            q = int(tot["num"]["queries"])
            hits = int(tot["num"]["cachehits"])
            dns = dict(queries=q, cache_hit_pct=r1(100 * hits / q if q else None),
                       recursion_ms=r1((f(tot.get("recursion", {}).get("time", {}).get("avg")) or 0) * 1000),
                       recursion_median_ms=r1((f(tot.get("recursion", {}).get("time", {}).get("median")) or 0) * 1000),
                       timed_out=int(tot["num"].get("queries_timed_out") or 0))
            if self.prev_dns and now > self.prev_dns[0] and q >= self.prev_dns[1]:
                dns["qps"] = r1((q - self.prev_dns[1]) / (now - self.prev_dns[0]), 2)
            self.prev_dns = (now, q)
            ov = self.api.get("unbound/overview/totals/10")
            dns.update(total_logged=ov.get("total"),
                       blocked=(ov.get("blocked") or {}).get("total"), blocked_pct=f((ov.get("blocked") or {}).get("pcnt")),
                       local_pct=f((ov.get("local") or {}).get("pcnt")),
                       blocklist=ov.get("blocklist_size"),
                       top_domains=[dict(domain=k.rstrip("."), count=v.get("total"), pct=f(v.get("pcnt")))
                                    for k, v in list((ov.get("top") or {}).items())[:TOP_N]],
                       top_blocked=[dict(domain=k.rstrip("."), count=v.get("total"))
                                    for k, v in list((ov.get("top_blocked") or {}).items())[:TOP_N]]
                       if isinstance(ov.get("top_blocked"), dict) else [])
            roll = self.api.get("unbound/overview/rolling/86400/1", timeout=25)
            per: Dict[str, int] = {}
            for bucket in roll.values():
                for ip, v in (bucket or {}).items():
                    if ip:
                        per[ip] = per.get(ip, 0) + int(v.get("count") or 0)
            dns["queries_24h"] = sum(per.values())
            dns["top_clients"] = [dict(ip=ip, name=self.name(ip), count=c)
                                  for ip, c in sorted(per.items(), key=lambda x: -x[1])[:TOP_N]]
            s["dns"] = dns
        except Exception as e:
            log.warning("unbound: %s", e)
        try:
            t = self.api.get("diagnostics/system/system_time")
            info = self.api.get("diagnostics/system/system_information")
            res = self.api.get("diagnostics/system/system_resources").get("memory", {})
            s["sys"] = dict(uptime=t.get("uptime"), boottime=t.get("boottime"), loadavg=t.get("loadavg"),
                            hostname=info.get("name"), versions=info.get("versions"),
                            mem_used_mb=r1(f(res.get("used_frmt")), 0), mem_total_mb=r1(f(res.get("total_frmt")), 0),
                            arc_mb=r1(f(res.get("arc_frmt")), 0))
        except Exception as e:
            log.debug("system: %s", e)
        self.slow = s
        self.slow_at = now

    def poll(self) -> Dict[str, Any]:
        now = time.time()
        if now - self.slow_at >= int(self.opts.get("slow_interval", 60)):
            self.slow_poll(now)
        ifs = self.interfaces(now)
        gws = self.gateways()
        st: Dict[str, Any] = dict(online="on", status="online", updated=int(now))
        st.update(self.slow)
        st["interfaces"] = ifs
        st["wan"] = ifs.get(self.opts.get("wan_interface", "wan"), {})
        st["lan"] = ifs.get(self.opts.get("lan_interface", "lan"), {})
        st["gateways"] = list(gws.values())
        st["gw_wan"] = gws.get(self.opts.get("wan_gateway", "WAN_DHCP"), {})
        st["pf"] = self.pf(now)
        try:
            st["top"] = self.talkers()
        except Exception as e:
            log.warning("top talkers: %s", e)
            st["top"] = dict(lan=[], wan=[])
        lan = st["top"]["lan"]
        st["top_talker"] = (lan[0]["name"] or lan[0]["ip"]) if lan else "none"
        # not every gateway online -> degraded
        if any(g.get("status") not in ("Online", None) for g in gws.values()):
            st["status"] = "degraded"
        return st


def get_path(d: dict, path: str) -> Any:
    for p in path.split("."):
        d = d.get(p) if isinstance(d, dict) else None
    return d


def publish_discovery(client: mqtt.Client, host: str, st: dict) -> None:
    uid = "opnsense_stats_" + host.replace(".", "_")
    dev = {"identifiers": [uid], "name": "OPNsense Stats", "manufacturer": "OPNsense",
           "model": MODEL, "configuration_url": f"https://{host}/"}
    vers = (st.get("sys") or {}).get("versions") or []
    if vers:
        dev["sw_version"] = vers[0]
    for comp, oid, name, key, extra in ENTITIES:
        tpl = "{{ value_json.%s }}" % key
        cfg = {"name": name, "unique_id": f"{uid}_{oid}", "device": dev,
               "state_topic": f"{BASE}/state", "value_template": tpl,
               "availability_topic": f"{BASE}/status"}
        for k, v in extra.items():
            cfg[k] = v if v is not None else f"{BASE}/attrs"
        client.publish(f"homeassistant/{comp}/{uid}/{oid}/config", json.dumps(cfg), retain=True)
    log.info("Published discovery for %d entities (%s)", len(ENTITIES), uid)


def flat_state(st: dict) -> dict:
    """Small state message for the numeric sensors (the full detail goes to the Status attributes)."""
    out = {"status": st.get("status"), "online": st.get("online"), "top_talker": st.get("top_talker")}
    for _, _, _, key, _ in ENTITIES:
        if "." in key:
            v = get_path(st, key)
            head, tail = key.split(".", 1)
            out.setdefault(head, {})[tail] = v
    return out


def main() -> None:
    opts = load_options()
    logging.getLogger().setLevel(getattr(logging, str(opts.get("log_level", "INFO")).upper(), logging.INFO))
    host = opts["host"]
    interval = int(opts.get("poll_interval", 10))
    api = Api(host, opts["api_key"], opts["api_secret"], bool(opts.get("verify_ssl", False)))
    poller = Poller(api, opts)

    ms = mqtt_settings(opts)
    while ms is None:
        time.sleep(60)
        ms = mqtt_settings(opts)
    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2, client_id="opnsense_stats")
    if ms["username"]:
        client.username_pw_set(ms["username"], ms["password"])
    client.will_set(f"{BASE}/status", "offline", retain=True)

    def on_connect(c, userdata, flags, reason_code, properties=None):
        log.info("MQTT connected: %s", reason_code)
        c.publish(f"{BASE}/status", "online", retain=True)

    def on_disconnect(c, userdata, flags, reason_code, properties=None):
        log.warning("MQTT disconnected: %s", reason_code)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.connect(ms["host"], ms["port"], 60)
    client.loop_start()

    published = False
    fails = 0
    while True:
        t0 = time.time()
        try:
            st = poller.poll()
            fails = 0
        except Exception as e:
            fails += 1
            log.warning("OPNsense poll failed (%d): %s", fails, e)
            if fails < 3:
                time.sleep(interval)
                continue
            st = {"online": "off", "status": "offline", "error": str(e)}
        if not published and st.get("online") == "on":
            publish_discovery(client, host, st)
            published = True
        client.publish(f"{BASE}/state", json.dumps(flat_state(st)), retain=True)
        client.publish(f"{BASE}/attrs", json.dumps(st), retain=True)
        time.sleep(max(1.0, interval - (time.time() - t0)))


if __name__ == "__main__":
    main()
