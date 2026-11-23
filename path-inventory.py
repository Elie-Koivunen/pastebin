#!/usr/bin/env python3
import argparse
import os
import signal
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


# Global flag for graceful shutdown
shutdown_requested = False
interrupted = False


def signal_handler(signum, frame):
    """Handle Ctrl-C signal for graceful shutdown."""
    global shutdown_requested, interrupted
    shutdown_requested = True
    interrupted = True
    print("\n\nInterrupt received. Finishing current operations...")


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
    
    def get_counts(self):
        with self.lock:
            return {
                'files': self.total_files,
                'dirs': self.total_dirs,
                'size': self.total_size
            }


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


def write_report_to_file(counter, start_time, end_time, duration, path, output_file):
    """Write inventory report to file."""
    counts = counter.get_counts()
    
    with open(output_file, 'w') as f:
        f.write("="*60 + "\n")
        f.write("INVENTORY REPORT\n")
        f.write("="*60 + "\n")
        f.write(f"Path: {path}\n")
        f.write(f"Total Directories: {counts['dirs']:,}\n")
        f.write(f"Total Files: {counts['files']:,}\n")
        f.write(f"Total Size: {counts['size']:,} bytes ({counts['size'] / (1024*1024):.2f} MB)\n")
        f.write("="*60 + "\n")
        f.write(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")
        f.write(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}\n")
        f.write(f"Duration: {duration:.2f} seconds\n")
        f.write("="*60 + "\n")


def interval_reporter(counter, start_time, path, interval_seconds, output_file):
    """Thread function to print interval reports."""
    global shutdown_requested
    
    while not shutdown_requested:
        time.sleep(interval_seconds)
        
        if shutdown_requested:
            break
        
        counts = counter.get_counts()
        elapsed = time.time() - start_time
        
        print("\n" + "="*60)
        print(f"INTERVAL REPORT (elapsed: {elapsed:.1f}s)")
        print("="*60)
        print(f"Total Directories: {counts['dirs']:,}")
        print(f"Total Files: {counts['files']:,}")
        print(f"Total Size: {counts['size']:,} bytes ({counts['size'] / (1024*1024):.2f} MB)")
        print("="*60 + "\n")
        
        # Also write to file
        write_report_to_file(counter, start_time, time.time(), elapsed, path, output_file)


def main():
    parser = argparse.ArgumentParser(description='Inventory folders and files in a directory tree.')
    parser.add_argument('--path', required=True, help='Path to scan')
    parser.add_argument('--threads', type=int, default=8, help='Number of threads to use (default: 8)')
    parser.add_argument('--interval', type=int, default=30, help='Interval in seconds for progress reports (default: 30)')
    parser.add_argument('--output', help='Output file path (default: inventory_<timestamp>.txt in script directory)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        return 1
    
    if not os.path.isdir(args.path):
        print(f"Error: Path '{args.path}' is not a directory")
        return 1
    
    # Generate output filename if not provided
    if args.output:
        output_file = args.output
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(script_dir, f"inventory_{timestamp}.txt")
    
    # Start timer
    start_time = time.time()
    start_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    print(f"Start time: {start_time_str}")
    print(f"Output file: {output_file}")
    
    counter = InventoryCounter()
    
    print(f"Scanning {args.path} with {args.threads} threads...")
    print(f"Progress reports every {args.interval} seconds...")
    print("Collecting directories...")
    
    # Start interval reporter thread
    reporter_thread = threading.Thread(
        target=interval_reporter,
        args=(counter, start_time, args.path, args.interval, output_file),
        daemon=True
    )
    reporter_thread.start()
    
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
            future.result()
    
    # Stop interval reporter
    shutdown_requested = True
    reporter_thread.join(timeout=2)
    
    # Print results
    end_time = time.time()
    end_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))
    duration = end_time - start_time
    
    counts = counter.get_counts()
    
    print("\n" + "="*60)
    if interrupted:
        print("INVENTORY RESULTS (INTERRUPTED)")
    else:
        print("INVENTORY RESULTS")
    print("="*60)
    print(f"Path: {args.path}")
    print(f"Total Directories: {counts['dirs']:,}")
    print(f"Total Files: {counts['files']:,}")
    print(f"Total Size: {counts['size']:,} bytes ({counts['size'] / (1024*1024):.2f} MB)")
    print("="*60)
    print(f"Start time: {start_time_str}")
    print(f"End time: {end_time_str}")
    print(f"Duration: {duration:.2f} seconds")
    print("="*60)
    print(f"Report saved to: {output_file}")
    
    # Write final report to file
    write_report_to_file(counter, start_time, end_time, duration, args.path, output_file)
    
    if interrupted:
        return 130
    return 0


if __name__ == '__main__':
    exit(main())
