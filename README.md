# security
Demo vulnerability exploits in python

These scripts are purely educational

## Running
### Packet Sniffing
- `root@anna:~# python3 sniffer.py -i interface_name` || `root@anna:~# python3 sniffer.py --interface interface_name`
### Full Script
- `python main.py -h` - show help
- `python main.py target_ip router_ip interface` - run the attack
- Example: `python app.py 192.168.1.39 192.168.1.1 en0` - en0 is the default interface for OS X.

## How it works
### Man in the Middle
todo: wiki
