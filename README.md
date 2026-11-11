# OPNsense Stats

Polls an OPNsense firewall's API and publishes it to Home Assistant as the **OPNsense Stats** MQTT device:

- WAN / LAN throughput in Mbit/s (from the interface byte counters), link speed, errors and drops
- Top talkers: the busiest LAN hosts (named from Kea DHCP leases) and remote hosts (reverse DNS), with
  download / upload rates
- Gateways: status, latency, jitter and packet loss
- Packet filter: state count and limit, new states per second, rule matches per second
- DNS (Unbound): queries per second, cache hit rate, recursion time, queries in the last 24 h,
  top domains, top blocked domains, top clients
- System: uptime, load, memory, versions

The `Status` sensor carries the full detail as attributes. MQTT credentials come from the Mosquitto
add-on automatically.

## Install

1. Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add
   `https://github.com/richcj10/ha-opensese_Stats`.
2. Install **OPNsense Stats**, set `host`, `api_key` and `api_secret` on the **Configuration** tab, and start it.
3. Requires the Mosquitto broker add-on (MQTT credentials are taken from it automatically);
   to use another broker, set `mqtt_host`, `mqtt_user` and `mqtt_password`.

## Setup

In OPNsense, create an API key (System → Access → Users → API keys) and enter it as `api_key` /
`api_secret`. The key needs read access to Diagnostics, Gateways, Unbound and Kea.

The top-talkers call samples live traffic for a few seconds, so keep `poll_interval` at 10 s or more.

`strip_domain` (e.g. `home.arpa`) trims your local domain from host names. Interface keys (`wan`, `lan`,
`opt1`, …) and the gateway name (`WAN_DHCP`) can be changed if yours differ.

Part of [RackViewer](https://github.com/richcj10/RackViewer), a rack status display, which reads this
add-on's entities from Home Assistant.
