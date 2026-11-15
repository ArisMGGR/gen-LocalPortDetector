# netsentry

A small Linux daemon that keeps an inventory of every device on your local network and
notifies you when something unknown joins, or when traffic looks like ARP spoofing.

It runs as a hardened systemd service, uses only the Python standard library (no `pip install`),
and alerts through phone push notifications ([ntfy](https://ntfy.sh)), Slack/Discord/generic
webhooks, or email.

## How it works

Every `interval` seconds (default 60) netsentry sends an ARP request to every address in the
subnet over a raw socket. Every IPv4 device has to answer ARP to talk on the LAN, so this finds
devices that block ping and have no open ports. ARP traffic from other hosts during the sweep is
recorded too.

Each device is stored by MAC address in SQLite (`/var/lib/netsentry/devices.db`) together with its
IPs, vendor (from the MAC prefix), reverse-DNS hostname, first/last seen times and whether you
have **approved** it.

| Event | Severity | When |
|---|---|---|
| `new_device` | warning | A MAC address never seen before shows up |
| `unapproved_return` | warning | A device you haven't approved comes back after being offline |
| `ip_conflict` | critical | One IP is answered by several MACs (ARP spoofing or a misconfigured device) |
| `gateway_change` | critical | Your router's MAC address changes (classic man-in-the-middle sign) |
| `baseline` | warning | First run: everything present was recorded as trusted |
| `online` / `offline` / `ip_change` | info | Normal comings and goings, logged but not pushed by default |

Events from one scan go out as a single notification. Every event also goes to the journal,
to the database (`netsentry events`), to `/var/log/netsentry/events.jsonl` and to the daily log.

### Daily logs

The `logs/` folder inside the project (the folder you ran `install.sh` from) gets one readable file
per day, named like `2026-11-04.log`. You can read them without sudo. Everything
the service logs lands there as it happens: events, scan errors, failed notifications, start and
stop. On top of that:

- `Unapproved device online: ...` is added every 30 minutes for each unapproved device still on the
  network, until you approve it or it leaves
- `No logs` is added when nothing at all was written for 30 minutes, so a quiet file still shows
  the service is alive

```
2026-11-04 14:30:02 [INFO] No logs
2026-11-04 14:41:17 [WARNING] new_device: New device joined the network: 00:de:ad:be:ef:01 at 192.168.1.50
2026-11-04 15:00:03 [WARNING] Unapproved device online: 00:de:ad:be:ef:01 at 192.168.1.50
```

No new lines at all means the service isn't running. Dates and times are the server's local time.
`[storage] keep_events_days` also controls how long these files are kept.

The service keeps writing there only while the project folder stays where it is. If you move it,
run `sudo ./install.sh` again from the new location. The installer sets `daily_log_dir` in the
config and adds `/etc/systemd/system/netsentry.service.d/logs.conf`, which allows the service
into that one folder and hides the rest of `/home` from it.

## Requirements

- Linux with systemd, Python 3.8+ (Debian 11+, Ubuntu 20.04+, Fedora, Raspberry Pi OS, ...)
- A machine that is **always on and on the same network segment** as the devices you want to
  watch. A wired Raspberry Pi or a home server is ideal.
- Optional: `sudo apt install ieee-data` (or arp-scan/nmap) for MAC vendor names.

## Install

```bash
sudo ./setup.sh
```

This installs netsentry and then asks a few questions:

1. **Network**: confirms the detected interface and subnet, or lets you pick another.
2. **Notifications**: sets up ntfy (it suggests a random topic and tells you what to subscribe to
   in the app), a Slack/Discord/generic webhook, or email, and sends a test alert through each.
3. **Alerts**: whether to be told about devices coming and going, and whether to trust what is on
   the network right now.
4. Shows a summary, saves `/etc/netsentry/netsentry.conf`, optionally previews a scan, and enables and
   starts the service.

Run `sudo netsentry setup` at any time to change these answers; it edits the config in place and
keeps its comments.

The install step creates a `netsentry` system user, installs the program to `/opt/netsentry`, the
command to `/usr/local/bin/netsentry`, the config to `/etc/netsentry/netsentry.conf` and the unit to
`/etc/systemd/system/netsentry.service`. Running it again upgrades in place and keeps your config.

<details>
<summary>Manual setup instead</summary>

```bash
sudo ./install.sh                                  # install only, no questions
sudo nano /etc/netsentry/netsentry.conf            # set up [ntfy], [webhook] or [email]
sudo netsentry test-notify                         # check that the alert reaches you
sudo systemctl enable --now netsentry
```

</details>

On the first scan everything currently on the network is recorded as trusted and you get one
"Monitoring started" summary. **Go through that list once** (`sudo netsentry list`) and name the
devices you recognise. If something there is unfamiliar, `sudo netsentry revoke <mac>` it and
find out what it is. If you'd rather approve each device by hand, set `baseline_on_first_run = no`
before starting the service.

## Daily use

```bash
sudo netsentry list                 # all known devices
sudo netsentry list --unapproved    # only the ones you haven't approved
sudo netsentry approve aa:bb:cc:dd:ee:ff --name "Kitchen speaker"
sudo netsentry approve --all        # trust everything currently unapproved
sudo netsentry revoke aa:bb:cc:dd:ee:ff
sudo netsentry forget aa:bb:cc:dd:ee:ff   # it will alert as new if seen again
sudo netsentry events -n 100
sudo netsentry setup                # change network, notification or alert settings
systemctl status netsentry          # shows "N devices online" from the last scan
```

When you get a `new_device` alert: if it's yours (a guest's phone, a new gadget), approve it. If
not, check your router's DHCP client list for that MAC/IP, then block it there and change your
Wi-Fi password.

## Configuration

Every option is documented in [packaging/netsentry.conf](packaging/netsentry.conf). The ones you
are most likely to change:

- `[scan] interface` / `subnet`: which network to watch (default: the default-route interface
  and its subnet).
- `[scan] interval`: seconds between scans.
- `[storage] daily_log_dir` / `daily_log_check`: the daily log folder (empty disables it) and the
  seconds between its checks.
- `[general] min_severity`: set it to `info` to also be told about devices coming and going.
- `[detection] offline_after`: phones sleep and stop answering; raise this if you get flapping.

Restart after changes: `sudo systemctl restart netsentry`.

## What it can't see

netsentry is an early-warning tripwire, not a full intrusion detection system. Know its blind spots:

- **Only the local segment.** ARP doesn't cross routers. Devices on other VLANs, a separate
  guest network or behind another router are invisible unless you run an instance there too.
- **MAC spoofing.** An intruder who copies the MAC of an approved device looks like the approved
  device. If it uses a different IP, it shows up only as an `ip_change`; if it also copies the IP,
  nothing is detected (an `ip_conflict` needs two different MACs on one IP).
- **Randomized MACs.** Modern phones use a random MAC per Wi-Fi network (and some rotate it
  periodically), so the same phone can show up as "new" again. Alerts point out randomized MACs.
  You can turn the feature off per network on your own devices.
- **Wi-Fi extenders/mesh nodes in MAC-NAT mode** answer ARP for the clients behind them, so
  those clients appear under the extender's MAC.
- **Wi-Fi client isolation** on the access point can hide wireless clients from a wired monitor.
- **ARP spoofing aimed only at other hosts** on a switched network never reaches this machine.
  Gateway-change and conflict detection cover what this host can see.
- **IPv4 only.** A device that uses only IPv6 is not detected.

## Uninstall

```bash
sudo ./uninstall.sh            # keeps config, database and logs
sudo ./uninstall.sh --purge    # removes everything, including the netsentry user
```

The project's `logs/` folder is never removed by the uninstaller; delete it yourself if you want.

## Development

```bash
python3 -m unittest discover -s tests -v
sudo python3 -m netsentry scan                        # from the repo, no install needed
sudo python3 -m netsentry -c dev.conf run             # foreground daemon with your own config
```

`dev.conf` (and any other `*.conf` outside `packaging/netsentry.conf`) is git-ignored, so real tokens
and passwords stay out of commits.

## License

[MIT](LICENSE)
