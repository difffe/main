import os
import re
import struct
import hashlib
import win32security
import winreg
import wmi
import time
import colorama
from colorama import init, Fore


init(autoreset=True)

def Is_FilePresent(file_path):
    return os.path.exists(file_path) and not os.path.isdir(file_path)

def Is_PEExecutable(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            signature = struct.unpack('<H', header)[0]  
            return signature == 23117 
    except Exception as e:
        return False

def Is_FileSignatureValid(file_path):
    try:
        def get_hash(file_path):
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()

        def is_signed(file_path):
            try:
                authdata = win32security.Authenticode(file_path)
                return True
            except Exception as e:
                return False

        return is_signed(file_path)
    except Exception as e:
        return False

def check_prefetch():

    key_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    value_name = "EnablePrefetcher"
    
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, value_name)
        if value == 0:
            print("El Prefetch está desactivado.")
        else:
            print("El Prefetch está activado.")
        winreg.CloseKey(key)
    except FileNotFoundError:
        print(f"No se encontró la clave del registro: {key_path}")
    except PermissionError:
        print(f"No se tienen permisos suficientes para acceder a la clave del registro: {key_path}")
    except Exception as e:
        print(f"Ocurrió un error al acceder al registro: {e}")

def check_sysmain():

    try:
        c = wmi.WMI()
        for service in c.Win32_Service(Name="SysMain"):
            if service.Started:
                print("El servicio SysMain está activado.")
            else:
                print("El servicio SysMain está desactivado.")
    except Exception as e:
        print(f"Ocurrió un error al consultar el servicio SysMain: {e}")

def check_diagtrack():

    try:
        c = wmi.WMI()
        for service in c.Win32_Service(Name="DiagTrack"):
            if service.Started:
                print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] El servicio Diagtrack está activado.")
            else:
                print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] El servicio Diagtrack está desactivado.")
    except Exception as e:
        print(f"Ocurrió un error al consultar el servicio Diagtrack: {e}")

def csrss_and_diagtrack():
    username = os.getenv('USERNAME')

    file_path1 = r"C:\Search results.txt"
    file_path2 = r"C:\Search results2.txt"
    file_path_diagtrack = r"C:\Search results3.txt"

    regex_modified_extension = r"(?!.*(\.exe|\.dll|\\|\.dll\..*\.config|\.exe\.config)$)^[A-Z]:\\.*\..*"
    regex_dll_injection = r"^[A-Za-z]:\\.+?\.(?!exe).*$"
    regex_executed_file = r"^[A-Za-z]:\\.+?\.exe"
    regex_files_without_extension1 = r"^[A-Za-z]:\\(?:[^.\\]+\\)*[^.\\]+$"
    regex_files_without_extension2 = r"^\\\\?\\?\\(?:[^.\\]+\\)*[^.\\]+$"
    regex_diagtrack_pattern1 = r"^\\device\\harddiskvolume[0-99]\\((?!exe).)*$"
    regex_diagtrack_pattern2 = r"^\\device\\harddiskvolume((?!Exe|dll).)*$"

    max_line_length = 260
    printed_matches = []


    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing service CSRSS...{Fore.RESET}")
    time.sleep(10)
    for file_path in [file_path1, file_path2]:
        if Is_FilePresent(file_path):
            if os.path.isfile(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        for line in f:
                            try:
                                line = line.decode('utf-8')
                            except UnicodeDecodeError:
                                line = line.decode('latin-1')

                            if len(line) > max_line_length:
                                continue

                            colon_pos = line.find(':')
                            if colon_pos != -1 and colon_pos + 2 < len(line):
                                matched_string = line[colon_pos + 2:].strip()

                                if re.match(regex_modified_extension, matched_string):
                                    if matched_string not in printed_matches:
                                        if Is_FilePresent(matched_string):
                                            if os.path.exists(matched_string) and os.path.isfile(matched_string) and not Is_FileSignatureValid(matched_string):
                                                print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Not signed executable file with a modified extension: {matched_string}")
                                            else:
                                                print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Signed executable file with a modified extension: {matched_string}")
                                        else:
                                            print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Not present file with a modified extension: {matched_string}")

                                        printed_matches.append(matched_string)
                                    continue

                                if re.match(regex_dll_injection, matched_string):
                                    if matched_string not in printed_matches:
                                        if Is_FilePresent(matched_string):
                                            if os.path.exists(matched_string) and os.path.isfile(matched_string) and not Is_FileSignatureValid(matched_string):
                                                print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Not signed file: {matched_string}")
                                            else:
                                                print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Signed file: {matched_string}")
                                        printed_matches.append(matched_string)
                                    continue

                                if re.match(regex_executed_file, matched_string):
                                    if matched_string not in printed_matches:
                                        if Is_FilePresent(matched_string):
                                            if os.path.exists(matched_string) and os.path.isfile(matched_string) and not Is_FileSignatureValid(matched_string):
                                                print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Not signed file: {matched_string}")
                                            else:
                                                print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Signed file: {matched_string}")
                                        printed_matches.append(matched_string)
                                    continue

                                if re.match(regex_files_without_extension1, matched_string) or re.match(regex_files_without_extension2, matched_string):
                                    if not os.path.exists(matched_string):
                                        print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] [#] Executed & Not present file without extension: {matched_string}")

                except Exception as e:
                    print(f"Error processing file '{file_path}': {e}")
        else:
            print(f"[{Fore.YELLOW}CSRSS{Fore.RESET}] Please re-enter a valid file path: {file_path}")


    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing service Diagtrack...{Fore.RESET}")
    time.sleep(10)
    if Is_FilePresent(file_path_diagtrack):
        if os.path.isfile(file_path_diagtrack):
            try:
                with open(file_path_diagtrack, 'rb') as f:
                    for line in f:
                        try:
                            line = line.decode('utf-8')
                        except UnicodeDecodeError:
                            line = line.decode('latin-1')

                        if len(line) > max_line_length:
                            continue

                        colon_pos = line.find(':')
                        if colon_pos != -1 and colon_pos + 2 < len(line):
                            matched_string = line[colon_pos + 2:].strip()

                            if re.match(regex_diagtrack_pattern1, matched_string):
                                if Is_PEExecutable(matched_string) and not Is_FileSignatureValid(matched_string):
                                    print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] Executed & Not signed digital file: {matched_string}")
                                else:
                                    print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] Executed & Modified extension: {matched_string}")

                            elif re.match(regex_diagtrack_pattern2, matched_string):
                                if Is_PEExecutable(matched_string) and not Is_FileSignatureValid(matched_string):
                                    print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] Executed & Not signed digital file: {matched_string}")

            except Exception as e:
                print(f"Error processing file '{file_path_diagtrack}': {e}")
        else:
            print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] Please re-enter a valid file path: {file_path_diagtrack}")
    else:
        print(f"[{Fore.YELLOW}Diagtrack{Fore.RESET}] File not found: {file_path_diagtrack}")

if __name__ == "__main__":
    print("--------------------------------------------------")
    print("[Memory Scanner] Loading USNJournal into memory...")
    csrss_and_diagtrack()
    print("--------------------------------------------------")
    print("[Memory Scanner] USNJournal Memory Scan Complete")
    
input("Done, thanks for using #NotDiff")    
