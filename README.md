# check_opnsense
Icinga check command for OPNsense firewall monitoring

## Requirements

This check command depends on the following python modules:
 * enum
 * requests
 * argparse

**Installation on Debian / Ubuntu**
```
apt install python-enum34 python-requests
apt install python-enum34 python3-requests
```

**Installation on Redhat 6 / CentOS 6**
```
yum install python-argparse python-enum34 python34-requests
```

**Installation on Redhat 7 / CentOS 7**
```
yum install python-enum34 python-requests
```

## Usage

The ``icinga2`` folder contains the command defintion and service examples for use with Icinga2.

```shell
usage: check_opnsense.py [-h] -H HOSTNAME [-p PORT] --api-key API_KEY --api-secret
                         API_SECRET [-k] -m {updates} [-w TRESHOLD_WARNING]
                         [-c TRESHOLD_CRITICAL]

Check command OPNsense firewall monitoring

optional arguments:
  -h, --help            show this help message and exit

API Options:
  -H HOSTNAME, --hostname HOSTNAME
                        OPNsense hostname or ip address
  -p PORT, --port PORT  OPNsense https-api port
                        OPNsense hostname or ip address
  --api-key API_KEY     API key (See OPNsense user manager)
  --api-secret API_SECRET
                        API key (See OPNsense user manager)
  -k, --insecure        Don't verify HTTPS certificate

Check Options:
  -m {updates}, --mode {updates}
                        Mode to use.
  -w TRESHOLD_WARNING, --warning TRESHOLD_WARNING
                        Warning treshold for check value
  -c TRESHOLD_CRITICAL, --critical TRESHOLD_CRITICAL
                        Critical treshold for check value

```

## Create API credentials

Go to the user manager and select the user you want to use for API access. Click the ``+`` icon in the ``API keys`` section to add a new API key, which triggers a download of a tex file containing the key and secret.

This file should look similar to this one:

```
key=w86XNZob/8Oq8aC5r0kbNarNtdpoQU781fyoeaOBQsBwkXUt
secret=XeD26XVrJ5ilAc/EmglCRC+0j2e57tRsjHwFepOseySWLM53pJASeTA3
```

For further information have a look at the [opnsense documentation](https://docs.opnsense.org/development/how-tos/api.html).

## Examples

**Check for updates**
```shell
./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m updates
CRITICAL - 42 pending updates. Subsequent reboot required.

./check_opnsense.py -H <OPNSENSE_HOSTNAME> --api-key <API_KEY> --api-secret <API_SECRET>  -m updates
WARNING - 14 pending updates.
```
