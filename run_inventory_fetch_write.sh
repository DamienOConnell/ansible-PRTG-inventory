#!/usr/bin/env bash

python3 inventory_fetch_write.py --list --outfile hosts.json
ansible-inventory -vvvv -i hosts.json --list


