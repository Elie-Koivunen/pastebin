#!/usr/bin/env python3
"""
Inventory Script for PowerScale OneFS
Counts files and directories in a directory tree with multithreaded scanning.
Optimized for large-scale filesystems with hundreds of millions of folders and billions of files.
READ-ONLY: Does not copy, move, or modify any data. Only reads metadata.
"""

__version__ = "2.1.0"

import argparse
import os
import signal
import sys
import time
import threading
import queue
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


# Global flag for graceful shutdown
shutdown_requested = False
interrupted = False
MAX_MEMORY_MB = 1024  # 1GB limit


def signal_handler(signum, frame):
    """Handle Ctrl-C signal for graceful shutdown."""
    global shutdown_requested, interrupted
    shutdown_requested = True
    interrupted = True
    print("\n\nInterrupt received. Finishing current operations...")


signal.signal(signal.SIGINT, signal_handler)


def get_memory_usage_mb():
    """Get current memory usage in MB."""
    process = psutil.Process()
    return process.memory_info().rss / (1024 * 1024)


def check_memory_limit():
    """Check if memory usage exceeds limit and warn or shutdown."""
    mem_mb = get_memory_usage_mb()
    if mem_mb > MAX_MEMORY_MB:
        print(f"\nWARNING: Memory usage {mem_mb:.1f} MB exceeds limit of {MAX_MEMORY_MB} MB")
        if mem_mb > MAX_MEMORY_MB * 1.2:  # 20% over limit
            print("ERROR: Memory usage critically high. Shutting down.")
            global shutdown_requested
            shutdown_requested = True
            return False
    return True


class InventoryCounter:
    def __init__(self):
        self.total_files = 0
        self.total_dirs = 0
        self.total_size = 0
        self.scanned_dirs = 0
        self.lock = Lock()
    
    def add_files(self, count, size):
        with self.lock:
            self.total_files += count
            self.total_size += size
    
    def add_dirs(self, count):
        with self.lock:
            self.total_dirs += count
    
    def increment_scanned(self):
        with self.lock:
            self.scanned_dirs += 1
    
    def get_counts(self):
        with self.lock:
            return {
                'files': self.total_files,
                'dirs': self.total_dirs,
                'size': self.total_size,
                'scanned_dirs': self.scanned_dirs
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


def directory_discovery(base_path, dir_queue, counter, max_queue_size=10000):
    """
    Recursively discover directories and add them to a queue.
    This allows streaming instead of loading all directories into memory.
    """
    global shutdown_requested
    
    dirs_to_process = [base_path]
    
    while dirs_to_process and not shutdown_requested:
        # Check memory limit periodically
        if not check_memory_limit():
            break
        
        current_dir = dirs_to_process.pop(0)
        
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if shutdown_requested:
                        break
                    if entry.is_dir():
                        dirs_to_process.append(entry.path)
                        counter.add_dirs(1)
                        # Add to queue for workers to scan
                        try:
                            dir_queue.put(entry.path, timeout=1)
                        except queue.Full:
                            # Queue is full, wait a bit
                            time.sleep(0.1)
                            dir_queue.put(entry.path, timeout=5)
                    elif entry.is_file():
                        counter.add_files(1, entry.stat().st_size if hasattr(entry, 'stat') else 0)
        except (PermissionError, OSError) as e:
            print(f"Error accessing {current_dir}: {e}")
    
    # Signal that discovery is complete
    dir_queue.put(None)


def write_report_to_file(counter, start_time, end_time, duration, path, output_file):
    """Write inventory report to file."""
    counts = counter.get_counts()
    mem_mb = get_memory_usage_mb()
    
    with open(output_file, 'w') as f:
        f.write("="*60 + "\n")
        f.write("INVENTORY REPORT\n")
        f.write("="*60 + "\n")
        f.write(f"Version: {__version__}\n")
        f.write(f"Path: {path}\n")
        f.write(f"Total Directories: {counts['dirs']:,}\n")
        f.write(f"Total Files: {counts['files']:,}\n")
        f.write(f"Total Size: {counts['size']:,} bytes ({counts['size'] / (1024*1024):.2f} MB)\n")
        f.write(f"Directories Scanned: {counts['scanned_dirs']:,}\n")
        f.write(f"Peak Memory Usage: {mem_mb:.1f} MB\n")
        f.write("="*60 + "\n")
        f.write(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}\n")
        f.write(f"End time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}\n")
        f.write(f"Duration: {duration:.2f} seconds\n")
        f.write("="*60 + "\n")
        f.write("NOTE: This is a READ-ONLY operation. No data was copied, moved, or modified.\n")
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
        mem_mb = get_memory_usage_mb()
        
        print("\n" + "="*60)
        print(f"INTERVAL REPORT (elapsed: {elapsed:.1f}s)")
        print("="*60)
        print(f"Memory Usage: {mem_mb:.1f} MB / {MAX_MEMORY_MB} MB")
        print(f"Total Directories: {counts['dirs']:,}")
        print(f"Directories Scanned: {counts['scanned_dirs']:,}")
        print(f"Total Files: {counts['files']:,}")
        print(f"Total Size: {counts['size']:,} bytes ({counts['size'] / (1024*1024):.2f} MB)")
        if counts['scanned_dirs'] > 0:
            rate = counts['scanned_dirs'] / elapsed
            print(f"Scan Rate: {rate:.1f} dirs/sec")
        print("="*60 + "\n")
        
        # Check memory limit
        if not check_memory_limit():
            break
        
        # Also write to file
        write_report_to_file(counter, start_time, time.time(), elapsed, path, output_file)


def main():
    global shutdown_requested, interrupted
    
    parser = argparse.ArgumentParser(
        description='Inventory folders and files in a directory tree. Optimized for large-scale filesystems. READ-ONLY: Does not copy, move, or modify any data.',
        epilog=f'Version: {__version__} | Memory limit: {MAX_MEMORY_MB} MB'
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--path', required=True, help='Path to scan')
    parser.add_argument('--threads', type=int, default=8, help='Number of threads to use (default: 8)')
    parser.add_argument('--interval', type=int, default=30, help='Interval in seconds for progress reports (default: 30)')
    parser.add_argument('--output', help='Output file path (default: inventory_<timestamp>.txt in script directory)')
    parser.add_argument('--queue-size', type=int, default=10000, help='Directory queue size (default: 10000)')
    
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
    print(f"Queue size: {args.queue_size}")
    print("Starting directory discovery and scanning...")
    
    # Create directory queue for streaming
    dir_queue = queue.Queue(maxsize=args.queue_size)
    
    # Start interval reporter thread
    reporter_thread = threading.Thread(
        target=interval_reporter,
        args=(counter, start_time, args.path, args.interval, output_file),
        daemon=True
    )
    reporter_thread.start()
    
    # Start directory discovery thread
    discovery_thread = threading.Thread(
        target=directory_discovery,
        args=(args.path, dir_queue, counter, args.queue_size),
        daemon=True
    )
    discovery_thread.start()
    
    # Scan directories in parallel using queue
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        
        while True:
            try:
                dir_path = dir_queue.get(timeout=1)
                
                if dir_path is None:
                    # Discovery complete
                    break
                
                future = executor.submit(scan_directory, dir_path, counter)
                futures.append(future)
                dir_queue.task_done()
                
            except queue.Empty:
                if not discovery_thread.is_alive():
                    # Discovery thread finished, check queue one more time
                    try:
                        dir_path = dir_queue.get_nowait()
                        if dir_path is None:
                            break
                        future = executor.submit(scan_directory, dir_path, counter)
                        futures.append(future)
                        dir_queue.task_done()
                    except queue.Empty:
                        break
                continue
        
        # Wait for all scanning to complete
        completed = 0
        for future in as_completed(futures):
            if shutdown_requested:
                print(f"\nShutdown requested. Completed {completed}/{len(futures)} directories before interrupt.")
                executor.shutdown(wait=False, cancel_futures=True)
                break
            
            # Check memory limit periodically
            if completed % 100 == 0:
                if not check_memory_limit():
                    break
            
            completed += 1
            if completed % 1000 == 0 or completed == len(futures):
                mem_mb = get_memory_usage_mb()
                print(f"Scanned {completed}/{len(futures)} directories (Memory: {mem_mb:.1f} MB)")
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
    print(f"Version: {__version__}")
    print(f"Path: {args.path}")
    print(f"Total Directories: {counts['dirs']:,}")
    print(f"Directories Scanned: {counts['scanned_dirs']:,}")
    print(f"Total Files: {counts['files']:,}")
    print(f"Total Size: {counts['size']:,} bytes ({counts['size'] / (1024*1024):.2f} MB)")
    if counts['scanned_dirs'] > 0:
        rate = counts['scanned_dirs'] / duration
        print(f"Average Scan Rate: {rate:.1f} dirs/sec")
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
