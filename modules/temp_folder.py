import os
import glob
import time
from colorama import Fore, Style
from .utils import is_file_signed

def scan_temp_folder():
    temp_folder = os.environ.get('TEMP', '')
    if not temp_folder:
        print(f"{Fore.RED}[TEMP]{Fore.RESET} TEMP environment variable is not set.")
        return set()

    results = set()

    for ext in ['exe', 'dll']:
        search_pattern = os.path.join(temp_folder, f'*.{ext}')
        files = glob.glob(search_pattern)

        for file_path in files:
            if not is_file_signed(file_path):
                results.add((file_path, ext.upper()))

    print(f"{Style.BRIGHT}{Fore.MAGENTA}[Memory Scanner] Analyzing TEMP files...{Fore.RESET}")
    time.sleep(10)
    
    if results:
        for file_path, ext in results:
            print(f"{Fore.BLUE}[TEMP]{Fore.RESET} Unsigned files in temp folder: {file_path} ({ext})")
    else:
        print(f"{Fore.BLUE}[TEMP]{Fore.RESET} No unsigned files found in TEMP folder.")

    return results
