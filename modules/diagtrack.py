import os
import re
import time
from colorama import Fore, Style
from .utils import is_file_present, is_file_signed

def analyze_diagtrack(file_path):
    regex_diagtrack_pattern1 = r"^\\device\\harddiskvolume[0-99]\\((?!exe).)*$"
    regex_diagtrack_pattern2 = r"^\\device\\harddiskvolume.+?\.exe$"
    system32_path = "\\device\\harddiskvolume3\\windows\\system32\\"

    unique_files = set()

    print(f"{Style.BRIGHT}{Fore.CYAN}[Memory Scanner] Analyzing Diagtrack service...{Fore.RESET}")
    time.sleep(10)

    if is_file_present(file_path) and os.path.isfile(file_path):
        try:
            with open(file_path, 'rb') as f:
                for line in f:
                    try:
                        line = line.decode('utf-8')
                    except UnicodeDecodeError:
                        line = line.decode('latin-1')

                    if len(line) > 260:
                        continue

                    colon_pos = line.find(':')
                    if colon_pos != -1 and colon_pos + 2 < len(line):
                        matched_string = line[colon_pos + 2:].strip()

                        if matched_string.startswith(system32_path):
                            continue

                        if re.match(regex_diagtrack_pattern1, matched_string):
                            if matched_string not in unique_files:
                                unique_files.add(matched_string)
                                print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} Executed & File with modified extension: {matched_string}")
                                if is_file_present(matched_string):
                                    if is_file_signed(matched_string):
                                        print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} File with modified extension is signed: {matched_string}")
                                    else:
                                        print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} File with modified extension is not signed: {matched_string}")
                                else:
                                    print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} Executed & Not present file with modified extension: {matched_string}")

                        elif re.match(regex_diagtrack_pattern2, matched_string):
                            if matched_string not in unique_files:
                                unique_files.add(matched_string)
                                print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} Executed & .exe file: {matched_string}")
                                if is_file_present(matched_string):
                                    if is_file_signed(matched_string):
                                        print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} .exe file is signed: {matched_string}")
                                    else:
                                        print(f"{Fore.GREEN}[Diagtrack]{Fore.RESET} .exe file is not signed: {matched_string}")

        except Exception as e:
            print(f"Error processing file '{file_path}': {e}")
    else:
        print(f"[{Style.BRIGHT}{Fore.GREEN}Diagtrack{Fore.RESET}] File not found or invalid: {file_path}")