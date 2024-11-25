#!/usr/bin/env python3

import argparse
import subprocess
import os
import socket
import dns.resolver
import csv
import json
from datetime import datetime

def display_version():
    """Return the version of the script."""
    return "Script version: 0.5"

def display_help(parser):
    """Display the help menu of the script."""
    parser.print_help()

def format_table(data):
    """Format the data as an indented table.
    Parameters:
    - data (list of tuple): Data to format.
    Returns:
    - str: Formatted table string.
    """
    col_widths = [max(len(str(x)) for x in col) for col in zip(*data)]
    lines = []
    for index, row in enumerate(data):
        line = '  '.join([str(row[i]).ljust(col_widths[i]) for i in range(len(row))])
        lines.append(line)
        if index == 0:  # After the header, add a separation line.
            lines.append('  '.join(['-' * col_widths[i] for i in range(len(row))]))
    return '\n'.join(lines)

def get_dc_lw(domain):
    """Execute the Likewise command and parse its output to display domain controllers.
    Parameters:
    - domain (str): The domain name to look up.
    Returns:
    - list: List of tuples containing the domain controller and its IP address.
    """
    lw_path = "/usr/likewise/bin/lw-get-dc-list"
    # Check if the Likewise command exists.
    if not os.path.exists(lw_path):
        return [("Controller", "IP Address"), ("ERROR", "LIKEWISE not found")]
    cmd = [lw_path, domain]
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.split('\n')
    dc_lines = [line for line in lines if "Name =" in line]
    data = [("Controller", "IP Address")]
    for line in dc_lines:
        name = line.split("Name = '")[1].split("',")[0]
        address = line.split("Address = '")[1].split("'")[0]
        data.append((name, address))
    # Sort data by domain controller name, excluding header.
    data[1:] = sorted(data[1:], key=lambda x: x[0])
    return data

def get_dc_dns(domain):
    """Retrieve DNS SRV records and related data for the given domain.
    Parameters:
    - domain (str): The domain name to look up.
    Returns:
    - list: List of tuples containing the target FQDN, IP address, reverse lookup, and match state.
    """
    data = [("TARGET FQDN", "IP ADDRESS", "REVERSE LOOKUP", "MATCH-STATE")]
    try:
        srv_records = dns.resolver.query(f'_ldap._tcp.dc._msdcs.{domain}', 'SRV')
        for record in srv_records:
            target_fqdn = record.target.to_text().rstrip('.')
            try:
                ip_record = dns.resolver.query(target_fqdn, 'A')[0]
                ip_address = ip_record.address
                try:
                    reverse_lookup = socket.gethostbyaddr(ip_address)[0]
                    if target_fqdn == reverse_lookup:
                        match_state = "MATCH"
                    else:
                        match_state = "MISMATCH"
                except socket.herror:
                    reverse_lookup = "N/A"
                    match_state = "N/A"
                data.append((target_fqdn, ip_address, reverse_lookup, match_state))
            except Exception:
                data.append((target_fqdn, "N/A", "N/A", "N/A"))
    except Exception as e:
        return [("ERROR", str(e))]
    # Sort data by target FQDN, excluding header.
    data[1:] = sorted(data[1:], key=lambda x: x[0])
    return data

def dump_data(switch, domain, data, dump_format):
    """Dump the data into a file based on the provided format.
    Parameters:
    - switch (str): Switch used to generate the data ('lw' or 'dns').
    - domain (str): The domain name.
    - data (list of tuple): Data to be saved.
    - dump_format (str): Format to save data in (csv, table, json).
    Returns:
    - str: Status message indicating success or failure.
    """
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f"{domain}-{switch.upper()}-{timestamp}.{dump_format}"
    try:
        if dump_format == "csv":
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(data[1:])  # Exclude headers for file storage
        elif dump_format == "json":
            with open(filename, 'w') as jsonfile:
                json.dump([dict(zip(data[0], row)) for row in data[1:]], jsonfile, indent=4)
        else:  # default to table
            with open(filename, 'w') as txtfile:
                txtfile.write(format_table(data))
        return f"Data saved to {filename}"
    except Exception as e:
        return f"Error saving data: {str(e)}"

def main():
    """Main function to handle arguments and call respective functions."""
    parser = argparse.ArgumentParser(add_help=False, description="This script is intended to assess what ad dc are available via likewise and via dns srv query. This helps in identifying inconsistencies between what the ad dc listing and DNS resolution. This script also facilitatest to dump the info into e.g. csv or json to be further processed. This script is not intrusive and does not modify any settings on the cluster or on the domain.")
    parser.add_argument("--version", action="store_true", help="Display script version.")
    parser.add_argument("--help", action="store_true", help="Display the help menu.")
    parser.add_argument("--get-dc-lw", metavar="DOMAIN", type=str, help="Execute the lw-get-dc-list command with the given DOMAIN.")
    parser.add_argument("--get-dc-dns", metavar="DOMAIN", type=str, help="Display the DNS SRV response and related data for the given DOMAIN.")
    parser.add_argument("--get-dc-all", metavar="DOMAIN", type=str, help="Run both --get-dc-lw and --get-dc-dns for the given DOMAIN.")
    parser.add_argument("--dump", action="store_true", help="Save the output into a file.")
    parser.add_argument("--dump-format", choices=["table", "csv", "json"], default="csv", help="Specify the format to save the output. Default is csv.")
    args = parser.parse_args()

    data = None
    switch_used = None

    if args.version:
        print(display_version())
    elif args.help:
        display_help(parser)
    elif args.get_dc_lw:
        switch_used = "lw"
        data = get_dc_lw(args.get_dc_lw)
        print(format_table(data))
    elif args.get_dc_dns:
        switch_used = "dns"
        data = get_dc_dns(args.get_dc_dns)
        print(format_table(data))
    elif args.get_dc_all:
        switch_used = "all"

        data_lw = get_dc_lw(args.get_dc_all)
        print("\n--get-dc-lw results--")
        print(format_table(data_lw))

        data_dns = get_dc_dns(args.get_dc_all)
        print("\n--get-dc-dns results--")
        print(format_table(data_dns))

        data = [("Source", "results")]
        for item in data_lw[1:]:
            data.append(("lw", f"{item[0]} - {item[1]}"))
        for item in data_dns[1:]:
            data.append(("dns", f"{item[0]} - {item[1]} - {item[2]} - {item[3]}"))

    if args.dump and data and switch_used:
        if switch_used == "all":
            print(dump_data(switch_used, args.get_dc_all, data, "table"))
        else:
            print(dump_data(switch_used, getattr(args, f'get_dc_{switch_used}'), data, args.dump_format))

    # If no main function switches are used, default to showing the help.
    if not any([args.version, args.help, args.get_dc_lw, args.get_dc_dns, args.get_dc_all, args.dump]):
        display_help(parser)

if __name__ == "__main__":
    main()
