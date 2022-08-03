#!/usr/bin/env python3

# -*- coding: utf-8 -*-


import argparse
import configparser
import requests
import re
import json
from pprint import pprint

CONFIG_FILE = "prtg.ini"
config = configparser.ConfigParser()
config.read_file(open(CONFIG_FILE))


def get_tag_set(devicelist: list) -> set:
    # Return the unique set of tags in this device dictionary
    tagset = set(())

    for device in devicelist:
        if device.get("tags"):
            for tag in device["tags"].split(" "):
                if "ansible-" in tag:
                    tag = tag.replace("ansible-", "")
                    tagset.add(tag)
    return tagset


def fix_tags(devicelist: list) -> list:
    # strip 'ansible-' string from tags
    for device in devicelist:
        if device.get("tags"):
            for tag in device["tags"].split(" "):
                if "ansible-" in tag:
                    tag = tag.replace("ansible-", "")
                    device["tags"] = tag
                    break
            # CLEAR THE TAGS HERE
    return devicelist


def clean_devices(devicelist: list, valid_tags: set) -> list:
    """
    1. Remove devices that don't have an 'ansible-' tag in them.
    2. Remove 'ansible-' prefix from tags to make proper group names, like 'ciscosmb'
    """

    def clean_name(name: str, ip_address: str) -> str:
        """
        Remove IP address pattern.
        remove brackets.
        Remove spaces.
        If nothing remains, use the IP address as hostname.
        """
        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        new_name = re.sub(ip_pattern, "", name)
        new_name = re.sub("[_]+", "-", new_name)
        new_name = new_name.replace(" ", "")
        new_name = new_name.replace("(", "")
        new_name = new_name.replace(")", "")
        if len(new_name) == 0:
            new_name = ip_address
        return new_name

    matching_devices = []

    for device in devicelist:
        if device.get("tags"):
            # There may be multiple tags, space-separated
            for tag in device["tags"].split(" "):
                if "ansible-" in tag:
                    tag = tag.replace("ansible-", "")
                    assert tag in valid_tags
                    device["tags"] = tag
                    device["name"] = clean_name(device["name"], device["host"])
                    matching_devices.append(device)

    return matching_devices


def main():

    # PRTG Server IP or DNS/hostname
    server = config.get("prtg", "prtg_server")
    # PRTG Username
    user = config.get("prtg", "prtg_user")
    # PRTG Password
    password = config.get("prtg", "prtg_passhash")
    # PRTG Tag
    tag = config.get("prtg", "prtg_tag")
    # FQDN for hostname manipulation

    if tag == "none":
        tag = False

    if not tag:
        print("Not filtering on tags\n")
        search_payload = (
            "content=devices&columns=objid,device,status,name,active,host,group,tags&username="
            + user
            + "&passhash="
            + password
            + ""
        )
        print(search_payload)
    else:
        print("Filtering on tag: {tag}\n")
        search_payload = (
            "content=devices&columns=objid,device,status,name,active,host,group,tags&filter_tags=@tag("
            + tag
            + ")&username="
            + user
            + "&passhash="
            + password
            + ""
        )

    headers = {
        "Content-Type": "application/yang-data+json",
        "Accept": "application/yang-data+json",
    }

    # beginning of API URL
    url = "https://" + server + "/api/table.json?"
    api_search_string = url + search_payload
    req = requests.get(
        api_search_string, params=search_payload, headers=headers, verify=True
    )

    jsonget = req.json()
    devices = jsonget["devices"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--outfile")
    parser.add_argument("--host", action="store")
    args = parser.parse_args()

    if args.outfile:
        outfile = args.outfile
    else:
        outfile = "output.json"

    # Get a set of tags, used to populate the empty dictionary
    tag_set = get_tag_set(devices)

    devices = clean_devices(devices, tag_set)

    # Prepare the group structure
    inventory = {"all": {"hosts": {}, "children": {}}}

    for group_tag in tag_set:
        inventory["all"]["children"][group_tag] = {}
        inventory["all"]["children"][group_tag]["hosts"] = {}

    # Clean data to match tag set
    for device in devices:

        inventory["all"]["children"][device["tags"]]["hosts"][device["name"]] = {}
        inventory["all"]["children"][device["tags"]]["hosts"][device["name"]][
            "ansible_host"
        ] = device["host"]

    with open(outfile, mode="w") as one_rec:
        json.dump(inventory, one_rec, indent=4)


if __name__ == "__main__":
    main()
