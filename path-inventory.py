#!/usr/bin/env python3
import argparse
import os
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle Ctrl-C signal for graceful shutdown."""
    global shutdown_requested
    shutdown_requested = True
    print("\n\nInterrupt received. Shutting down gracefully...")
    sys.exit(130)  # Standard exit code for SIGINT


signal.signal(signal.SIGINT, signal_handler)


class InventoryCounter:
    def __init__(self):
        self.total_files = 0
        self.total_dirs = 0
        self.total_size = 0
        self.lock = Lock()
    
    def add_files(self, count, size):
        with self.lock:
            self.total_files += count
            self.total_size += size
    
    def add_dirs(self, count):
        with self.lock:
            self.total_dirs += count


def scan_directory(dir_path, counter):
    """Scan a single directory and count files and subdirectories."""
    global shutdown_requested
    if shutdown_requested:
        return dir_path, 0, 0, 0
    
    try:
        files_count = 0
        dirs_count = 0
        size = 0
        
        with os.scandir(dir_path) as entries:
            for entry in entries:
                if shutdown_requested:
                    break
                if entry.is_file():
                    files_count += 1
                    try:
                        size += entry.stat().st_size
                    except (OSError, AttributeError):
                        pass
                elif entry.is_dir():
                    dirs_count += 1
        
        counter.add_files(files_count, size)
        counter.add_dirs(dirs_count)
        
        return dir_path, files_count, dirs_count, size
    except (PermissionError, OSError) as e:
        print(f"Error scanning {dir_path}: {e}")
        return dir_path, 0, 0, 0


def collect_directories(base_path, counter):
    """Recursively collect all directories to scan."""
    directories = []
    
    try:
        with os.scandir(base_path) as entries:
            for entry in entries:
                if entry.is_dir():
                    directories.append(entry.path)
                    # Recursively collect subdirectories
                    subdirs = collect_directories(entry.path, counter)
                    directories.extend(subdirs)
                    counter.add_dirs(len(subdirs))
                elif entry.is_file():
                    counter.add_files(1, entry.stat().st_size if hasattr(entry, 'stat') else 0)
    except (PermissionError, OSError) as e:
        print(f"Error accessing {base_path}: {e}")
    
    return directories


def main():
    parser = argparse.ArgumentParser(description='Inventory folders and files in a directory tree.')
    parser.add_argument('--path', required=True, help='Path to scan')
    parser.add_argument('--threads', type=int, default=8, help='Number of threads to use (default: 8)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        return 1
    
    if not os.path.isdir(args.path):
        print(f"Error: Path '{args.path}' is not a directory")
        return 1
    
    # Start timer
    start_time = time.time()
    start_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    print(f"Start time: {start_time_str}")
    
    counter = InventoryCounter()
    
    print(f"Scanning {args.path} with {args.threads} threads...")
    print("Collecting directories...")
    
    # Collect all directories recursively
    directories = collect_directories(args.path, counter)
    
    # Add the base directory itself
    counter.add_dirs(1)
    
    print(f"Found {len(directories)} directories to scan...")
    print("Scanning directories in parallel...")
    
    # Scan directories in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_directory, dir_path, counter): dir_path 
                   for dir_path in directories}
        
        completed = 0
        for future in as_completed(futures):
            if shutdown_requested:
                print(f"\nShutdown requested. Completed {completed}/{len(directories)} directories before interrupt.")
                executor.shutdown(wait=False, cancel_futures=True)
                break
            completed += 1
            if completed % 100 == 0 or completed == len(directories):
                print(f"Scanned {completed}/{len(directories)} directories")
    
    # Print results
    end_time = time.time()
    end_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
    duration = end_time - start_time
    
    print("\n" + "="*50)
    print("INVENTORY RESULTS")
    print("="*50)
    print(f"Path: {args.path}")
    print(f"Total Directories: {counter.total_dirs:,}")
    print(f"Total Files: {counter.total_files:,}")
    print(f"Total Size: {counter.total_size:,} bytes ({counter.total_size / (1024*1024):.2f} MB)")
    print("="*50)
    print(f"Start time: {start_time_str}")
    print(f"End time: {end_time_str}")
    print(f"Duration: {duration:.2f} seconds")
    print("="*50)
    
    return 0


if __name__ == '__main__':
    exit(main())
