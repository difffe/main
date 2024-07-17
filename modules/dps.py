import os
import re
import time
from colorama import Fore, Style

def analyze_dps(file_path):
    print(f"{Style.BRIGHT}{Fore.CYAN}[Memory Scanner] Analyzing DPS service...{Fore.RESET}")
    time.sleep(10)

    exe_with_dates = {}

    regex_pattern = r'!!([^\s!]+\.exe)!(\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})'

    if os.path.isfile(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            matches = re.findall(regex_pattern, content)
            unique_files = set()

            if matches:
                for match in matches:
                    exe_file = match[0]
                    compile_dates = match[1].split(':')

                    if exe_file in exe_with_dates:
                        if compile_dates not in exe_with_dates[exe_file]:
                            exe_with_dates[exe_file].append(compile_dates)
                    else:
                        exe_with_dates[exe_file] = [compile_dates]

                for exe_file, dates_list in exe_with_dates.items():
                    if len(dates_list) > 1:
                        if exe_file not in unique_files:
                            unique_files.add(exe_file)
                            print(f"{Fore.GREEN}[DPS] {Fore.RESET} Founding file: {exe_file} - Different compilation dates:")
                            for dates in dates_list:
                                print(f"{Fore.GREEN}[DPS] {Fore.RESET} -{Fore.YELLOW} {exe_file} - {dates[0]}:{dates[1]}:{dates[2]}")

            else:
                print(f"{Fore.GREEN}[DPS] {Fore.RESET} No suspicious execution patterns found in {file_path}")

        except Exception as e:
            print(f"Error processing file '{file_path}': {e}")
    else:
        print(f"{Fore.GREEN}[DPS] {Fore.RESET} File not found or invalid: {file_path}")