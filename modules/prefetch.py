import os
import time
import re
from colorama import Fore, Style

def search_prefetch_files():
    prefetch_folder = r'C:\Windows\Prefetch'
    suspicious_files = set()

    if os.path.isdir(prefetch_folder):
        files = os.listdir(prefetch_folder)
        for filename in files:
            
            if filename.lower().endswith('.pf'):
                full_path = os.path.join(prefetch_folder, filename)
                
                if ".exe" not in filename.lower():
                    suspicious_files.add(full_path)
    else:
        print(f"{Fore.RED}[Prefetch]{Fore.RESET} Prefetch directory not found.")

    return suspicious_files

def analyze_prefetch():
    print(f"{Style.BRIGHT}{Fore.MAGENTA}[Memory Scanner] Analyzing Prefetch files...{Fore.RESET}")
    time.sleep(10)

    suspicious_files = search_prefetch_files()

    if suspicious_files:
        for file in suspicious_files:
            print(f"{Fore.RED}[PREFETCH]{Fore.RESET} .pf files with modified extension: {file}")
    else:
        print(f"{Fore.GREEN}[Memory Scanner]{Fore.RESET} No suspicious .pf files found without '.EXE' in name.")
