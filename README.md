# Python Tools for Forensics and Data Recovery and Monitoring

## Quick Notes on Operation

### Directory Tree Walker
 1. Source the ```setup_settings``` script.
    * $ . setup_settings
 2. Run ```walker.py```.
    * $ bin/walker.py --help

### IP Monitor
 1. Script help
    * $ bin/monitor_ip.py --help
 2. Run ```monitor_ip.py``` in data collection mode.
    * $ sudo bin/monitor_ip.py -a 192.168.1.106 -p 8000 -P TCP -l logs/monitor_ip.log -d data/monitor_ip.db
 3. Dump SQLite database
    * $ sudo bin/monitor_ip.py -l logs/monitor_ip.log -d data/monitor_ip.db -b
