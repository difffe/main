#### old version
import os
import re
import struct
import hashlib
import win32security
import time
import psutil
from colorama import init, Fore

init(autoreset=True)

def is_file_present(file_path):
    return os.path.exists(file_path) and not os.path.isdir(file_path)

def is_pe_executable(file_path):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            signature = struct.unpack('<H', header)[0]
            return signature == 23117  # Valid PE signature
    except Exception as e:
        return False

def is_file_signed(file_path):
    try:
        authdata = win32security.Authenticode(file_path)
        return True
    except Exception as e:
        return False

def analyze_explorer():
    system32_path = os.path.join(os.environ['SystemRoot'], 'System32').lower()
    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing service Explorer...{Fore.RESET}")
    time.sleep(10)

    printed_paths = set()

    for proc in psutil.process_iter(['exe']):
        try:
            if proc.info['exe'] and proc.info['exe'].endswith('.exe'):
                process_exe = proc.info['exe']
                
                if not process_exe.lower().startswith(system32_path):
                
                    if process_exe not in printed_paths:
                        print(f"[{Fore.RED}Explorer{Fore.RESET}] Executed File: {process_exe}")
                        printed_paths.add(process_exe)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            print(f"Error processing process '{proc.info.get('name', 'Unknown')}' or its executable: {e}")

def analyze_diagtrack(file_path):
    regex_diagtrack_pattern1 = r"^\\device\\harddiskvolume[0-99]\\((?!exe).)*$"
    regex_diagtrack_pattern2 = r"^\\device\\harddiskvolume.+?\.exe$"

    max_line_length = 260

    system32_path = "\\device\\harddiskvolume3\\windows\\system32\\"

    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing service Diagtrack...{Fore.RESET}")
    time.sleep(10)

    if is_file_present(file_path) and os.path.isfile(file_path):
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

                        if matched_string.startswith(system32_path):
                            continue

                        if re.match(regex_diagtrack_pattern1, matched_string):
                            print(f"[{Fore.RED}Diagtrack{Fore.RESET}] Executed & File with modified extension: {matched_string}")

                            if is_file_present(matched_string):
                                if is_file_signed(matched_string):
                                    print(f"[{Fore.RED}Diagtrack{Fore.RESET}] File with modified extension is signed: {matched_string}")
                                else:
                                    print(f"[{Fore.RED}Diagtrack{Fore.RESET}] File with modified extension is not signed: {matched_string}")
                            else:
                                print(f"[{Fore.RED}Diagtrack{Fore.RESET}] Executed & Not present file with modified extension: {matched_string}")

                        elif re.match(regex_diagtrack_pattern2, matched_string):
                            print(f"[{Fore.RED}Diagtrack{Fore.RESET}] Executed & .exe file: {matched_string}")

                            if is_file_present(matched_string):
                                if is_file_signed(matched_string):
                                    print(f"[{Fore.RED}Diagtrack{Fore.RESET}] .exe file is signed: {matched_string}")
                                else:
                                    print(f"[{Fore.RED}Diagtrack{Fore.RESET}] .exe file is not signed: {matched_string}")

        except Exception as e:
            print(f"Error processing file '{file_path}': {e}")
    else:
        print(f"[{Fore.RED}Diagtrack{Fore.RESET}] File not found or invalid: {file_path}")

def analyze_csrss(file_paths):
    regex_csrss_pattern1 = r"(?!.*(\.exe|\.dll|\\|\.dll\..*\.config|\.exe\.config)$)^[A-Z]:\\.*\..*"
    regex_csrss_pattern2 = r"^[A-Za-z]:\\.+?\.(?!exe).*$"
    regex_csrss_pattern3 = r"^[A-Za-z]:\\.+?\.exe"
    regex_csrss_pattern4 = r"^[A-Za-z]:\\(?:[^.\\]+\\)*[^.\\]+$"
    regex_csrss_pattern5 = r"^\\\\?\\?\\(?:[^.\\]+\\)*[^.\\]+$"

    max_line_length = 260
    printed_matches = []

    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing service CSRSS...{Fore.RESET}")
    time.sleep(10)

    for file_path in file_paths:
        if is_file_present(file_path) and os.path.isfile(file_path):
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

                            if re.match(regex_csrss_pattern1, matched_string):
                                if matched_string not in printed_matches:
                                    if is_file_present(matched_string):
                                        if is_file_signed(matched_string):
                                            print(f"[{Fore.RED}CSRSS{Fore.RESET}] [#] Executed & Signed executable file with a modified extension: {matched_string}")
                                        else:
                                            print(f"[{Fore.RED}CSRSS{Fore.RESET}] [#] Executed & Not signed executable file with a modified extension: {matched_string}")
                                    else:
                                        print(f"[{Fore.RED}CSRSS{Fore.RESET}] [#] Executed & Not present file with a modified extension: {matched_string}")

                                    printed_matches.append(matched_string)

                            elif re.match(regex_csrss_pattern2, matched_string) or re.match(regex_csrss_pattern3, matched_string):
                                if matched_string not in printed_matches:
                                    if is_file_present(matched_string):
                                        if is_file_signed(matched_string):
                                            print(f"[{Fore.RED}CSRSS{Fore.RESET}] [#] Executed & Signed file: {matched_string}")
                                        else:
                                            print(f"[{Fore.RED}CSRSS{Fore.RESET}] [#] Executed & Not signed file: {matched_string}")
                                    printed_matches.append(matched_string)

                            elif re.match(regex_csrss_pattern4, matched_string) or re.match(regex_csrss_pattern5, matched_string):
                                if not os.path.exists(matched_string):
                                    print(f"[{Fore.RED}CSRSS{Fore.RESET}] [#] Executed & Not present file without extension: {matched_string}")

            except Exception as e:
                print(f"Error processing file '{file_path}': {e}")
        else:
            print(f"[{Fore.RED}CSRSS{Fore.RESET}] Please re-enter a valid file path: {file_path}")

def analyze_minecraft():
    minecraft_path = os.path.join(os.getenv('APPDATA'), '.minecraft')

    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing Minecraft process...{Fore.RESET}")
    time.sleep(10)

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            process_name = proc.info['name'].lower()
            process_exe = proc.info['exe']

            if process_name == "javaw.exe" and minecraft_path.lower() in process_exe.lower():
                process = psutil.Process(proc.info['pid'])
                for module in process.memory_maps():
                    try:
                        module_name = os.path.basename(module.path).lower()
                        if module_name.endswith('.jar'):
                            if is_file_malicious(module.path):
                                print(f"[{Fore.RED}Minecraft{Fore.RESET}] Detected malicious mod: {module.path}")
                            elif verify_jar_signature(module.path):
                                print(f"[{Fore.RED}Minecraft{Fore.RESET}] Detected signed mod: {module.path}")
                            else:
                                print(f"[{Fore.RED}Minecraft{Fore.RESET}] Detected mod: {module.path}")
                    
                    except Exception as e:
                        print(f"Error processing module '{module.path}': {e}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            print(f"Error processing process '{proc.info.get('name', 'Unknown')}' or its executable: {e}")

def analyze_minecraft_from_file(txt_file):
    keywords = [
        "autoclick", "reach", "killaura", "slinky", "vape", "dream",
        "liquidbounce", "impact", "matix", "sigma", "flux", 
        "huzuni", "jesus", "fly", "speed", "xray", "teleport", 
        "noclip", "scaffold", "timer", "bhop", "freecam", "godmode",
        "cheatbreaker", "future", "hyperium", "jello", "pyro", "summit",
        "velocity", "zues", "butterfly", "aura", "autoarmor", "autoblock",
        "autototem", "clickgui", "criticals", "fly", "glide", "inventorywalk",
        "jesus", "killaura", "nameprotect", "nofall", "noknockback",
        "nohunger", "norender", "noslowdown", "notouch", "nuke", "op", "panic",
        "phase", "reach", "regen", "safewalk", "scaffold", "spammer", "speed",
        "step", "strafe", "timer", "tpaura", "triggerbot", "velocity", "wallhack"
    ]

    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing Minecraft from file '{txt_file}'...{Fore.RESET}")
    time.sleep(2)

    try:
        with open(txt_file, 'r', encoding='utf-8') as file:
            content = file.read()

        for keyword in keywords:
            if keyword in content:
                print(f"[{Fore.RED}Minecraft{Fore.RESET}] Detected suspicious keyword '{keyword}' in file '{txt_file}'")

    except Exception as e:
        print(f"Error reading file '{txt_file}': {e}")

if __name__ == "__main__":
    file_paths_csrss = [r"C:\csrss1.txt", r"C:\csrss2.txt"]
    file_path_diagtrack = r"C:\diagtrack.txt"
    file_path_minecraft = r"C:\javaw.txt"

    print("--------------------------------------------------")
    print("[Memory Scanner] Loading USNJournal into memory...")

    analyze_explorer()
    analyze_diagtrack(file_path_diagtrack)
    analyze_csrss(file_paths_csrss)
    analyze_minecraft()
    
    if os.path.exists(file_path_minecraft) and os.path.isfile(file_path_minecraft):
        analyze_minecraft_from_file(file_path_minecraft)
    else:
        print(f"[{Fore.RED}Minecraft{Fore.RESET}] Please re-enter a valid file path: {file_path_minecraft}")

    print("--------------------------------------------------")
    input("Good Bye! Lucky, thanks for using #NotDiff")
