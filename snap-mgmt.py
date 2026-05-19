import argparse
from collections import defaultdict
from operator import itemgetter
import sys
import os
import subprocess
from datetime import datetime
import socket
import textwrap   

# add features
# - proximate storage utilization per snapshot path
# - group snapshots by dates
# - group-by-name and end grouping string to first _numeral

# Script general variables
myscript_name = "snap-mgmt"
myscript_author = "Elie.Koivunen@Dell.com"
myscript_contributors = ""
myscript_version = "0.8"
myscript_hostname = socket.gethostname()
myscript_publishdate = "2024-05-24"
myscript_license_src = "Copyright 2024 Dell Permission is hereby granted, free of charge, to any personobtaining  a copy of this software and associated documentation files (the-Software),to deal in the Software without restriction, including without limitation  the rights touse, copy, modify, merge, publish, distribute, sublicense, and/or  sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. All changes should be  shared back."
myscript_warning_src = "THE SOFTWARE IS PROVIDED AS-IS, WITHOUT WARRANTYOF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENTSHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHERLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
myscript_howto_src = "This script reads the saved verbose snapshot listing and categorizes the information accordingly. First you would run --snapshot-assess to collect information of the currently existing snapshots on the system. This info would be saved into a snaphsot-info-<timestamp>.src file. Having this feature gives the chance to capture point in time snapshot statistics for more extensive analysis. Once you have a source file, you can list grouped information of snapshots based on the designated absolute path or a grouping based on the prefix of a snapshot schedule name. You have the option of sorting the output based on entries, state, size name or path in an ascending or descending order. With the search switch, you have the option of searching based on absolute path or a snapshot schedule name prefix."

# Function to format the text with newlines every 78 characters without splitting words
def format_txt_width_src(input_string, width=78):
    # Use textwrap.fill to wrap text without splitting words
    return textwrap.fill(input_string, width)

# wrap large text strings to a count that per default would fit a screen view
myscript_license = format_txt_width_src(myscript_license_src)
myscript_warning = format_txt_width_src(myscript_warning_src)
myscript_howto = format_txt_width_src(myscript_howto_src)

# Set the script's base filename as a repurposable variable
def myscript_filename():
    return os.path.basename(sys.argv[0])
# Function to provide information about the script

def myscript_about():
    # Display script metadata
    print("\n===============================================================================")
    print("\n")
    print(f"Script Name: {myscript_name}")
    print(f"Author: {myscript_author}")
    print(f"Contributors: {myscript_contributors}")
    print(f"Version: {myscript_version}")
    print(f"Current hostname: {myscript_hostname}")
    print(f"Publish Date: {myscript_publishdate}")
    print("\n")
    print(f"License: {myscript_license}")
    print("\n")
    print(f"{myscript_warning}")
    print("\n")
    print(f"{myscript_howto}")
    print("\n")
    print("\n===============================================================================")
    print("\n")


def get_prefix(name):
    return '-'.join(name.split('-')[:-1])

def parse_size(size_str):
    size_str = size_str.lower()
    if 'k' in size_str:
        return float(size_str.replace('k', '')) * 1024
    elif 'm' in size_str:
        return float(size_str.replace('m', '')) * 1024 * 1024
    elif 'g' in size_str:
        return float(size_str.replace('g', '')) * 1024 * 1024 * 1024
    elif 't' in size_str:
        return float(size_str.replace('t', '')) * 1024 * 1024 * 1024 * 1024
    else:
        return float(size_str)

def convert_to_terabytes(size_in_bytes):
    size_in_terabytes = size_in_bytes / (1024 * 1024 * 1024 * 1024)
    return "{:.12f}".format(size_in_terabytes)

def group_by_name(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        entries = defaultdict(lambda: defaultdict(int))
        paths = defaultdict(str)
        for line in lines[2:]:
            if line.startswith('-') or line.startswith('Total:') or line.startswith('ID'):
                continue  # Skip non-data lines
            row = list(filter(None, line.split(' ')))
            if len(row) < 14:
                print(f"Skipping row due to insufficient columns: {row}")
                continue
            name = row[1]
            path = row[2]
            size = parse_size(row[9])
            state = row[13]
            prefix = get_prefix(name)
            entries[(prefix, state)]['count'] += 1
            entries[(prefix, state)]['size'] += size
            paths[prefix] = path
    return entries, paths

def group_by_path(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        entries = defaultdict(lambda: defaultdict(int))
        paths = defaultdict(str)
        for line in lines[2:]:
            if line.startswith('-') or line.startswith('Total:') or line.startswith('ID'):
                continue  # Skip non-data lines
            row = list(filter(None, line.split(' ')))
            if len(row) < 14:
                print(f"Skipping row due to insufficient columns: {row}")
                continue
            name = row[1]
            path = row[2]
            size = parse_size(row[9])
            state = row[13]
            prefix = get_prefix(name)
            entries[(path, state)]['count'] += 1
            entries[(path, state)]['size'] += size
            paths[path] = path  # Set the path to the path itself
    return entries, paths


def sort_entries(entries, paths, sort_by, sort_type):
    sort_column_options = {"entries": 0, "size": 1, "state": 2, "name": 3, "path": 4}
    sort_index = sort_column_options.get(sort_by, 4)

    entries_list = [(data['count'], convert_to_terabytes(data['size']), state, prefix, paths[prefix]) for (prefix, state), data in entries.items()]

    entries_list.sort(key=itemgetter(sort_index), reverse=(sort_type == "desc"))

    return entries_list

def print_entries_by_name(entries_list):
    print("{:<10}{:<20}{:<10}{:<50}{:<100}".format("Entries", "Total Size(Tb) ", "State", "Name Prefix", "Path"))
    print("-"*140)
    for entry in entries_list:
        cleaned_entry = [field.strip() if isinstance(field, str) else field for field in entry]
        print("{:<10}{:<20}{:<10}{:<50}{:<100}".format(*cleaned_entry))

def print_entries_by_path(entries_list):
    print("{:<10}{:<20}{:<10}{:<100}".format("Entries", "Total Size(Tb) ", "State", "Path"))
    print("-"*105)
    for entry in entries_list:
        cleaned_entry = [field.strip() if isinstance(field, str) else field for field in entry]
        # Print the path instead of the name prefix
        print("{:<10}{:<20}{:<10}{:<100}".format(cleaned_entry[0], cleaned_entry[1], cleaned_entry[2], cleaned_entry[4]))
def search_entries(entries_list, search_string):
    if '/' in search_string:  # If the search string is a path
        print("{:<10}{:<20}{:<10}{:<100}".format("Entries", "Total Size(Tb) ", "State", "Path"))
        print("-"*105)
        for entry in entries_list:
            cleaned_entry = [field.strip() if isinstance(field, str) else field for field in entry]
            if search_string in cleaned_entry[3] or search_string in cleaned_entry[4]:
                print("{:<10}{:<20}{:<10}{:<100}".format(*cleaned_entry[:3], cleaned_entry[4]))
    else:  # If the search string is a name prefix
        print("{:<10}{:<20}{:<10}{:<50}{:<100}".format("Entries", "Total Size(Tb) ", "State", "Name Prefix", "Path"))
        print("-"*140)
        for entry in entries_list:
            cleaned_entry = [field.strip() if isinstance(field, str) else field for field in entry]
            if search_string in cleaned_entry[3] or search_string in cleaned_entry[4]:
                print("{:<10}{:<20}{:<10}{:<50}{:<100}".format(*cleaned_entry))


def snapshots_assess():
    command = ['isi', 'snapshot', 'snapshots', 'list', '--verbose', '--format=table']
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"snapshots-info_{timestamp}.src"
    with open(filename, 'w') as file:
        subprocess.run(command, stdout=file)

def filter_locks(entries_list):
    return [entry for entry in entries_list if entry[3] == 'Yes']


def main():
    parser = argparse.ArgumentParser(description='Process a file and group entries by name prefix or path.')
    parser.add_argument('--file', help='Path to the file to be read')
    parser.add_argument('--group-by-name', action='store_true', help='Group by name prefix')
    parser.add_argument('--group-by-path', action='store_true', help='Group by path')
    parser.add_argument('--sort-by', default='path', choices=['entries', 'state', 'size', 'name', 'path'], help='Sort column')
    parser.add_argument('--sort-type', default='asc', choices=['asc', 'desc'], help='Sort type')
    parser.add_argument('--snapshots-assess', action='store_true', help='Run snapshot assessment')
    parser.add_argument('--about', action='store_true', help='Information about the script')
    parser.add_argument('--search', help='Search for a specific string in name prefix or path')
    parser.add_argument('--locks', action='store_true', help='Only show entries with locks')
    args = parser.parse_args()

    if args.about:
        print("This is a script that processes a file and groups entries by name prefix or path.")
        myscript_about()    
    elif args.snapshots_assess:
        snapshots_assess()
    elif args.group_by_name or args.group_by_path or args.search:
        if args.file is None:
            print("The --file argument is required when using --group-by-name, --group-by-path or --search.")
            sys.exit(1)
        # If the search string contains a '/', group by path
        if args.search and '/' in args.search:
            entries, paths = group_by_path(args.file)
        # Otherwise, group by name
        else:
            entries, paths = group_by_name(args.file)
        entries_list = sort_entries(entries, paths, args.sort_by, args.sort_type)
        if args.locks:
            entries_list = filter_locks(entries_list)
        if args.search:  # If --search is provided
            search_entries(entries_list, args.search)
        elif args.group_by_name:  # If --group-by-name is provided
            print_entries_by_name(entries_list)
        elif args.group_by_path:  # If --group-by-path is provided
            print_entries_by_path(entries_list)

if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
