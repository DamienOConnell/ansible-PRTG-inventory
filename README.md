# ansible-PRTG-inventory

# ansible-PRTG-inventory

Pull inventory from PRTG REST API; export selected hosts to ansible inventory file.  
Provide PRTG data in config file.
Devices with PRTG tag 'ansible-' will be put in inventory groups.
Device entries are assumed to have an IP address against them.

Host names are cleaned by
- remove IP addresses, brackets, _- and finally spaces.
- If nothing remains, the host IP is used as the device name.

## Issues, to do

Error handling not yet implemented.
Current output format is JSON.
Add YAML output option.
Selector for tag filtering on / off.
argparse for all all arguments / input data / help. 
