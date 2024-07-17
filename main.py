import os
import time
from modules.explorer import analyze_explorer
from modules.diagtrack import analyze_diagtrack
from modules.dps import analyze_dps
from modules.csrss import analyze_csrss
from modules.bam import analyze_bam
from modules.prefetch import analyze_prefetch
from modules.temp_folder import scan_temp_folder
from modules.utils import read_last_lines
from colorama import init, Fore, Style

init()

def read_last_lines(file_path, num_lines=10):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            last_lines = lines[-num_lines:]
        return ''.join(last_lines).strip()
    except FileNotFoundError:
        return f"File not found: {file_path}"
    except Exception as e:
        return f"Error reading file {file_path}: {str(e)}"

def main():

    file_paths_csrss = [r"C:\csrss1.txt", r"C:\csrss2.txt"]
    file_path_diagtrack = r"C:\diagtrack.txt"
    file_path_dps = r"C:\dps.txt"

    print("--------------------------------------------------")
    print("[Memory Scanner] Loading USNJournal into memory...")

    analyze_explorer()
    analyze_diagtrack(file_path_diagtrack)
    analyze_dps(file_path_dps)
    analyze_csrss(file_paths_csrss)
    analyze_bam()
    
    pca_general_file = os.path.join(r'C:\Windows\appcompat\pca', 'PcaGeneralDb0.txt')
    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing file PcaGeneralDb0.txt:")
    time.sleep(3)
    pca_general_content = read_last_lines(pca_general_file, 10)
    print(f"{Fore.YELLOW}[PCA] {Fore.RESET}{pca_general_content}")

    pca_app_launch_file = os.path.join(r'C:\Windows\appcompat\pca', 'PcaAppLaunchDic.txt')
    print(f"{Fore.MAGENTA}[Memory Scanner] Analyzing file PcaAppLaunchDic.txt:")
    time.sleep(3)
    pca_app_launch_content = read_last_lines(pca_app_launch_file, 10)
    print(f"{Fore.YELLOW}[PCA] {Fore.RESET}{pca_app_launch_content}")

    scan_results = scan_temp_folder()
    analyze_prefetch()

    print("--------------------------------------------------")
    print("Thanks For using #NotDiff")

    try:
        while True:
            time.sleep(4)
    except KeyboardInterrupt:
        print("\nProgram interrupted and closing...")

if __name__ == "__main__":
    main()
