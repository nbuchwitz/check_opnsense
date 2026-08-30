# check_opnsense
Icinga check command for OPNsense firewall monitoring

## Requirements

This check command depends on the following python modules:
 * enum
 * requests
 * argparse

**Installation on Debian / Ubuntu**
```
apt install python3 python3-requests
```

**Installation on Rocky / Alma Linux 9**
```
yum install python3 python3-requests
```

**Installation on FreeBSD**
```
pkg install python3 py39-requests
```

## Usage

Add a check command definition and a service to Icinga2.

Use `./check_opnsense.py -h` to get instructions:

```shell
usage: check_opnsense.py [-h] [-V] -H HOSTNAME [-p PORT] [--api-key API_KEY] [--api-secret API_SECRET] [-t TIMEOUT] [-k] -m {updates,ipsec,interfaces,services,wireguard,disk,memory,swap,cpu,load}
                         [-w THRESHOLD_WARNING] [-c THRESHOLD_CRITICAL] [-v] [-f FILTER] [--filter-regex FILTER_REGEX] [-i INCLUDE]

Check command OPNsense firewall monitoring

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

API Options:
  -H, --hostname HOSTNAME
                        OPNsense hostname or ip address
  -p, --port PORT       OPNsense https-api port
  --api-key API_KEY     API key (See OPNsense user manager), defaults to $OPNSENSE_API_KEY
  --api-secret API_SECRET
                        API secret (See OPNsense user manager), defaults to $OPNSENSE_API_SECRET
  -t, --timeout TIMEOUT
                        API request timeout in seconds (default: 30)
  -k, --insecure        Don't verify HTTPS certificate

Check Options:
  -m, --mode {updates,ipsec,interfaces,services,wireguard,disk,memory,swap,cpu,load}
                        Mode to use.
  -w, --warning THRESHOLD_WARNING
                        Warning threshold for check value
  -c, --critical THRESHOLD_CRITICAL
                        Critical threshold for check value
  -v, --verbose         Show additional details, e.g. the items excluded by --filter
  -f, --filter FILTER   Comma separated list of items to exclude from the output and the exit code calculation. Example: 'Disk 1, Disk 2'.
  --filter-regex FILTER_REGEX
                        Exclude every item matching this regular expression. Example: 'lo[0-9]+'.
  -i, --include INCLUDE
                        Comma separated list of the only items to check. Everything else is excluded. Example: 'igb0, igb1'.
```

## Create API credentials

Go to the user manager and select the user you want to use for API access. Click the ``+`` icon in the ``API keys`` section to add a new API key, which triggers a download of a tex file containing the key and secret.

This file should look similar to this one:

```
key=w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt
secret=XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3
```

For further information have a look at the [opnsense documentation](https://docs.opnsense.org/development/how-tos/api.html).

Whatever you pass on the command line shows up in the process list of the monitoring host. Put the
credentials in the environment to keep them out of it:

```shell
export OPNSENSE_API_KEY=w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt
export OPNSENSE_API_SECRET=XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3
./check_opnsense.py -H <OPNSENSE_HOSTNAME> -m updates
```

For a permanent setup, keep the two variables in a file that only the monitoring user can read:

```shell
cat > /etc/check_opnsense.env <<'EOF'
OPNSENSE_API_KEY=w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt
OPNSENSE_API_SECRET=XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3
EOF
chmod 600 /etc/check_opnsense.env
```

The lines have no `export`, because that is the format systemd reads. Make the file belong to the
user icinga2 runs as, which is not the same on every distribution.

The check plugin itself does not read the file. Something has to put the variables into the
environment it runs in. Under systemd a drop-in does that for icinga2 and everything it starts:

```ini
# /etc/systemd/system/icinga2.service.d/opnsense.conf
[Service]
EnvironmentFile=/etc/check_opnsense.env
```

Run `systemctl daemon-reload` and restart icinga2 afterwards. In a shell, read the same file with
`set -a; . /etc/check_opnsense.env; set +a`.

## Filtering

Most modes let you skip items you are not interested in. Skipped items count neither for the output
nor for the exit code.

`-f/--filter` takes a comma separated list of names, for example `-f "/, /var"`. If the names share
a pattern, `--filter-regex 'lo[0-9]+'` saves you from listing them all.

`-i/--include` works the other way round. It checks the listed items and skips everything else.
`-f` and `--filter-regex` still apply on top of it.

Add `-v` to see what was left out:

```
[OK] Disk space is ok | /var=4%;80.0;90.0;0;100
[OK] /var has 190G of 200G (96.0%) free disk space
--- FILTERED ---
[FILTER] / is excluded by --filter
```

## Examples

***Check for updates***
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m updates
[CRITICAL] There are 43 updates available, total download size is 199.1MiB. This update requires a reboot.|upgrade_packages=42 reinstall_packages=1 remove_packages=0 available_updates=43

./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m updates
[WARNING] There are 14 updates available, total download size is 64.8MiB.|upgrade_packages=14 reinstall_packages=0 remove_packages=0 available_updates=14

./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m updates
[OK] - System up to date|upgrade_packages=0 reinstall_packages=0 remove_packages=0 available_updates=0
```

***Check for services***
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m services
[CRITICAL] 1 service(s) stopped: ddclient (ddclient)

--- RUNNING SERVICES ---
[RUNNING] Configd (configd)
[RUNNING] Cron (cron)
[RUNNING] Dnsmasq DNS/DHCP (dnsmasq)
[RUNNING] Gateway Watcher (dpinger/:watcher:)
[RUNNING] Gateway WAN (dpinger/WAN)
[RUNNING] Hostwatch (hostwatch)
[RUNNING] Users and Groups (login)
[RUNNING] Ntpd (ntpd)
[RUNNING] OpenVPN server company-vpn (openvpn/4711)
[RUNNING] Packet Filter (pf)
[RUNNING] System routing (routing)
[RUNNING] IPsec VPN (strongswan)
[RUNNING] System tunables (sysctl)
[RUNNING] Syslog-ng (syslog-ng)
[RUNNING] Unbound (unbound)
[RUNNING] Web GUI (webgui)
 | services_running=16 services_stopped=1
```

***Check interface status***

Options:

* `-f <device>` will not check `<device>` i.e. `-f igb0` will not check the igb0 interface.

One interface being down is enough to make the check critical. The check ignores interfaces that
are disabled in OPNsense.

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m interfaces
[OK] 2 interface(s) are up | interfaces_up=2 interfaces_down=0
[OK] interface igb0 is up
[OK] interface igb1 is up
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m interfaces
[CRITICAL] 1 interface(s) are down | interfaces_up=1 interfaces_down=1
[OK] interface igb0 is up
[CRITICAL] interface igb1 is down
```

***Check ipsec tunnel status***
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m ipsec
[WARNING] IPsec tunnels not connected: headquarter

./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m ipsec
[OK] IPsec tunnels connected: remote-office, headquarter
```

***Check wireguard tunnel status***
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m wireguard
[OK] 2/2 Wireguard peers are online
[OK] Peer host1 is online (8.8.8.4:35376)
[OK] Peer host2 is online (8.8.8.5:34376)
```

***Check available disk space***

Options:

* `-w` and `-c` define maximum disk usage i.e. `-w 80` will warn if disk usage exceeds 80%  
* `-f <mountpoint>` will not check `<mountpoint>` i.e. `-f /` will not check the root filesystem.

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m disk
[OK] Disk space is ok | /=2%;80.0;90.0;0;100
[OK] / has 201G of 222G (98.0%) free disk space
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m disk - w 1 -c 2.5
[WARNING] Disk space is low on 1 disk(s) | /=2%;1.0;2.5;0;100
[WARNING] / has only 201G of 222G (98.0%) free disk space
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m disk - w 1 -c 2
[CRITICAL] Disk space is critically low on 1 disk(s) | /=2%;1.0;2.0;0;100
[CRITICAL] / has only 201G of 222G (98.0%) free disk space
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m disk - w 1 -c 2 -f '/'
[UNKNOWN] No disks found
```

***Check memory***

Options:

* `-w` and `-c` define maximum memory usage i.e. `-w 80` will warn if memory usage exceeds 80% 

Opnsense systems **without ZFS**, not using ARC:
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m memory
[OK] Memory usage is 34% | memory=34%;80.0;90.0;0;100;

```

Opnsense systems **with ZFS**, using ARC:
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m memory -w 35 -c 50
[WARNING] Memory usage is 39% | memory=39%;35.0;50.0;0;100; arc_size=199MB;
Additional memory used for ARC: 199MB
```

***Check swap***

Options:

* `-w` and `-c` define maximum memory usage i.e. `-w 80` will warn if memory usage exceeds 80% 

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m swap
[OK] Total swap usage is 2% | /dev/md0=9%;80.0;90.0;0;100 /dev/gpt/swapfs=1%;80.0;90.0;0;100
Swap usage on /dev/md0 is 9%
Swap usage on /dev/gpt/swapfs is 1%
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m swap -f /dev/gpt/swapfs -c 8
[CRITICAL] Total swap usage is 9% | /dev/md0=9%;80.0;8.0;0;100
Swap usage on /dev/md0 is 9%
```

***Check CPU***

Options:

* `-w` and `-c` define maximum cpu usage i.e. `-w 80` will warn if cpu usage exceeds 80%

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m cpu
[OK] CPU usage is 1.9% | cpu_usage=1.9%;80.0;90.0;0;100
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m cpu -w 30 -c 40
[CRITICAL] CPU usage is 42.7% | cpu_usage=42.7%;1.0;1.2;0;100
```

***Check load***

Options: 

* `-w` and `-c` define maximum load i.e. `-w 2` will warn if any load time range exceeds 2. 

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m load
[OK] Load is ok. | load1=0.88;3.0;4.0;0; load5=0.72;3.0;4.0;0; load15=0.61;3.0;4.0;0;
[OK] load1 is 0.88
[OK] load5 is 0.72
[OK] load15 is 0.61
```

```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET> -m load -w 0.5 -c 0.8
[CRITICAL] Load is critical. | load1=1.34;0.5;0.8;0; load5=0.82;0.5;0.8;0; load15=0.65;0.5;0.8;0;
[CRITICAL] load1 is 1.34
[CRITICAL] load5 is 0.82
[WARNING] load15 is 0.65
```
