import os
import psutil
import time
from colorama import Fore, Style
from .utils import is_file_present, is_file_signed

def analyze_explorer():
    system32_path = os.path.join(os.environ['SystemRoot'], 'System32').lower()

    print(f"{Style.BRIGHT}{Fore.CYAN}[Memory Scanner] Analyzing Explorer service...{Fore.RESET}")
    time.sleep(10)

    printed_paths = set()

    for proc in psutil.process_iter(['exe']):
        try:
            if proc.info['exe'] and proc.info['exe'].endswith('.exe'):
                process_exe = proc.info['exe']

                if not process_exe.lower().startswith(system32_path):
                    if process_exe not in printed_paths:
                        print(f"{Fore.GREEN}[Explorer]{Fore.RESET} Executed File: {process_exe}")
                        printed_paths.add(process_exe)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            print(f"{Fore.RED}[Error]{Fore.RESET} Access denied: Insufficient privileges to access process information.")
        except Exception as e:
            print(f"Error processing process '{proc.info.get('name', 'Unknown')}' or its executable: {e}")
