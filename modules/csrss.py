import os
import re
import time
from colorama import Fore, Style
from .utils import is_file_present, is_file_signed

def analyze_csrss(file_paths):
    regex_csrss_pattern1 = r"(?!.*(\.exe|\.dll|\\|\.dll\..*\.config|\.exe\.config)$)^[A-Z]:\\.*\..*"
    regex_csrss_pattern2 = r"^[A-Za-z]:\\.+?\.(?!exe).*$"
    regex_csrss_pattern3 = r"^[A-Za-z]:\\.+?\.exe"
    regex_csrss_pattern4 = r"^[A-Za-z]:\\(?:[^.\\]+\\)*[^.\\]+$"
    regex_csrss_pattern5 = r"^\\\\?\\?\\(?:[^.\\]+\\)*[^.\\]+$"

    max_line_length = 260
    unique_files = set()

    print(f"{Style.BRIGHT}{Fore.CYAN}[Memory Scanner] Analyzing CSRSS service...{Fore.RESET}")
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
                                if matched_string not in unique_files:
                                    unique_files.add(matched_string)
                                    if is_file_present(matched_string):
                                        if is_file_signed(matched_string):
                                            print(f"{Fore.GREEN}[CSRSS]{Fore.RESET} [#] Executed & Signed executable file with a modified extension: {matched_string}")
                                        else:
                                            print(f"{Fore.GREEN}[CSRSS]{Fore.RESET} [#] Executed & Not signed executable file with a modified extension: {matched_string}")
                                    else:
                                        print(f"{Fore.GREEN}[CSRSS]{Fore.RESET} [#] Executed & Not present file with a modified extension: {matched_string}")

                            elif re.match(regex_csrss_pattern2, matched_string) or re.match(regex_csrss_pattern3, matched_string):
                                if matched_string not in unique_files:
                                    unique_files.add(matched_string)
                                    if is_file_present(matched_string):
                                        if is_file_signed(matched_string):
                                            print(f"{Fore.GREEN}[CSRSS]{Fore.RESET} [#] Executed & Signed file: {matched_string}")
                                        else:
                                            print(f"{Fore.GREEN}[CSRSS]{Fore.RESET} [#] Executed & Not signed file: {matched_string}")

                            elif re.match(regex_csrss_pattern4, matched_string) or re.match(regex_csrss_pattern5, matched_string):
                                if not os.path.exists(matched_string):
                                    if matched_string not in unique_files:
                                        unique_files.add(matched_string)
                                        print(f"{Fore.GREEN}[CSRSS]{Fore.RESET} [#] Executed & Not present file without extension: {matched_string}")

            except Exception as e:
                print(f"Error processing file '{file_path}': {e}")
        else:
            print(f"[{Style.BRIGHT}{Fore.GREEN}CSRSS{Fore.RESET}] Please re-enter a valid file path: {file_path}")