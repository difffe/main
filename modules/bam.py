import winreg
import time
from colorama import Fore, Style

def analyze_bam():
    base_path = r"SYSTEM\CurrentControlSet\Services\bam"
    sub_paths = [r"State\UserSettings", r"UserSettings"]

    print(f"{Style.BRIGHT}{Fore.CYAN}[Memory Scanner] Analyzing BAM entries...{Fore.RESET}")
    time.sleep(5)

    try:
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)

        for sub_path in sub_paths:
            full_path = f"{base_path}\\{sub_path}"
            try:
                key = winreg.OpenKey(reg, full_path)
                i = 0
                while True:
                    try:
                        sid = winreg.EnumKey(key, i)
                        if sid.endswith("1001") or sid.endswith("1002"):
                            sid_key = winreg.OpenKey(key, sid)
                            j = 0
                            while True:
                                try:
                                    value = winreg.EnumValue(sid_key, j)
                                    value_name = value[0]
                                    if value_name.startswith(r"\Device\HarddiskVolume") and not value_name.endswith(".exe"):
                                        print(f"{Fore.YELLOW}[BAM] {Fore.RESET}Executed File Modified: {value_name}{Fore.RESET}")
                                    j += 1
                                except OSError:
                                    break
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                print(f"{Fore.RED}[Error]{Fore.RESET} Path not found: {full_path}")

        winreg.CloseKey(reg)
    except OSError as e:
        print(f"{Fore.RED}[Error]{Fore.RESET} Failed to access registry: {e}")
        