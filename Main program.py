import os
import time
import hashlib
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

# Configuration
SIGNATURE_FILE = "malware_signatures.txt"
QUARANTINE_DIR = "C:/Quarantine"
SCAN_DIRECTORIES = ["C:/Users/YourUsername/Downloads", "C:/Program Files"]  # Add more directories as needed
LOG_FILE = "antivirus.log"

# Initialize logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Load known malware signatures
def load_signatures(signature_file):
    with open(signature_file, 'r') as file:
        signatures = file.read().splitlines()
    return signatures

# Calculate file hash (for caching and heuristic analysis)
def calculate_file_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Heuristic analysis: Check for suspicious file attributes
def heuristic_analysis(file_path):
    suspicious_keywords = [b"eval(", b"exec(", b"base64_decode(", b"shell_exec("]
    with open(file_path, 'rb') as file:
        content = file.read()
        for keyword in suspicious_keywords:
            if keyword in content:
                return True, f"Suspicious keyword found: {keyword.decode()}"
    return False, None

# Scan a file for malware signatures and heuristic analysis
def scan_file(file_path, signatures):
    # Signature-based detection
    with open(file_path, 'rb') as file:
        content = file.read()
        for signature in signatures:
            if signature.encode() in content:
                return True, f"Signature detected: {signature}"

    # Heuristic-based detection
    is_suspicious, reason = heuristic_analysis(file_path)
    if is_suspicious:
        return True, reason

    return False, None

# Quarantine infected files
def quarantine_file(file_path):
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    file_name = os.path.basename(file_path)
    quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
    os.rename(file_path, quarantine_path)
    logging.info(f"Quarantined: {file_path} -> {quarantine_path}")
    print(f"Quarantined: {file_path} -> {quarantine_path}")

# Real-time monitoring using watchdog
class FileMonitor(FileSystemEventHandler):
    def __init__(self, signatures):
        self.signatures = signatures
        self.file_hash_cache = {}  # Cache for file hashes to avoid rescanning unchanged files

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, file_path):
        file_hash = calculate_file_hash(file_path)
        if file_path in self.file_hash_cache and self.file_hash_cache[file_path] == file_hash:
            return  # Skip if file hasn't changed

        self.file_hash_cache[file_path] = file_hash
        threading.Thread(target=self.scan_and_quarantine, args=(file_path,)).start()

    def scan_and_quarantine(self, file_path):
        is_infected, reason = scan_file(file_path, self.signatures)
        if is_infected:
            logging.warning(f"Infected file detected: {file_path} (Reason: {reason})")
            print(f"Infected file detected: {file_path} (Reason: {reason})")
            quarantine_file(file_path)

# Main function
def main():
    # Load signatures
    signatures = load_signatures(SIGNATURE_FILE)

    # Start real-time monitoring
    print("Starting real-time monitoring...")
    event_handler = FileMonitor(signatures)
    observer = Observer()
    for directory in SCAN_DIRECTORIES:
        observer.schedule(event_handler, path=directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
