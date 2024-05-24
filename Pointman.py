import argparse
import magic
import os
import subprocess
import importlib
import sys

# ANSI escape codes for multi-colored text
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def setup_alias():
    alias_command_prefix = 'alias Pointman='
    bashrc_path = os.path.expanduser("~/.bashrc")

    # Check if alias already exists
    with open(bashrc_path, "r") as bashrc:
        lines = bashrc.readlines()
        if any(alias_command_prefix in line for line in lines):
            return

    # Prompt user for the desired path to the script if alias does not exist
    script_path = input(f"{MAGENTA}Pointman{RESET} can automatically add an {YELLOW}alias{RESET}, so that to use it in the future, you just have to type \"Pointman\". \n\nEnter the path of the {MAGENTA}Pointman{RESET} script to automatically set an {YELLOW}alias{RESET}: \n\n").strip()
    alias_command = f'alias Pointman="python3 {script_path}"'

    # Add alias to .bashrc
    with open(bashrc_path, "a") as bashrc:
        bashrc.write(f'\n# Alias for Pointman script\n{alias_command}\n')

    # Inform the user to source their .bashrc or restart the terminal
    print("Alias 'Pointman' has been added to your .bashrc.")
    print("Please run 'source ~/.bashrc' or restart your terminal to apply the changes.")

def identify_file(target_file, verbose):
    if not os.path.exists(target_file):
        print(f"{RED}\u2757Error:{RESET} The file {YELLOW}{target_file}{RESET} does not exist. Did you type it correctly?")
        return

    try:
        # Use the magic library to identify the file type
        file_type = magic.from_file(target_file)
        print(f"File Type Detected: {file_type}")

        # Additional output for verbose mode
        if verbose:
            if 'executable' in file_type.lower() or 'application/x-dosexec' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mcapa\033[0m for PE emulation: (https://github.com/mandiant/capa) \n\033[95mqu1cksc0pe\033[0m for PE emulation: (https://github.com/CYB3RMX/Qu1cksc0pe) \n\033[95mPE Studio\033[0m for static analysis: (https://www.winitor.com/download) \n\033[95mPE-Bear\033[0m for static analyis: (https://github.com/hasherezade/pe-bear)")
            elif 'image' in file_type.lower() and ('jpeg' in file_type.lower() or 'png' in file_type.lower()):
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\nCheck for \033[95msteganography\033[0m with tools like these: https://github.com/topics/steganography-tools")
            elif 'pdf' in file_type.lower():
                print("\n[ANALYSIS RECOMMENDATIONS]\n\033[95mpdfid.py\033[0m to analyze objects: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py)\n\033[95mpdf-parser.py\033[0m to analyze & extract objects: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)")
            elif 'rich text format' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mrtfdump.py\033[0m to analyze and extract objects: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/rtfdump.py)")
            elif 'dll' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mcapa\033[0m for DLL emulation: (https://github.com/mandiant/capa) \n\033[95mqu1cksc0pe\033[0m for DLL emulation: (https://github.com/CYB3RMX/Qu1cksc0pe) \n\033[95mPE Studio\033[0m for static analysis: (https://www.winitor.com/download) \nPE-Bear for static analyis: (https://github.com/hasherezade/pe-bear)")
            elif 'ascii text' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\nSimple text file - recommend conducting static analysis.")                  
            elif 'ms windows shortcut' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mLECmd (LNK Explorer CMD)\033[0m from EZ Tools: (https://ericzimmerman.github.io/#!index.md)")                                
            elif 'xml 1.0 document, ascii text' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mxmldump.py\033[0m for static analysis: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/xmldump.py)")                     
            
            elif 'composite document file v2 document' in file_type.lower():
                print("\nMost likely .doc File (pre-2007)\n\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mzipdump.py\033[0m for extracting zip archive components: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/zipdump.py)\n\033[95moledump.py\033[0m for extracting macros: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py)\n\033[95molevba\033[0m for extracting macros: (https://github.com/decalage2/oletools/wiki/olevba)\n\033[95mexiftool\033[0m for metadata analysis: (https://github.com/exiftool/exiftool)\n\033[95mre-search.py\033[0m for de-obfuscation: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/re-search.py)\n\033[95mxmldump.py\033[0m for static analysis: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/xmldump.py)\n\033[95mViperMonkey\033[0m for VBA macro emulation: (https://github.com/decalage2/ViperMonkey)\n\033[95mEvilClippy\033[0mfor removing passwords from VBA projects: (https://github.com/outflanknl/EvilClippy)")  

            elif 'microsoft word 2007' in file_type.lower():
                print("\nMost likely .docx File (2007+)\n\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mzipdump.py\033[0m for extracting zip archive components: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/zipdump.py)\n\033[95mre-search.py\033[0m for de-obfuscation: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/re-search.py)\n\033[95mViperMonkey\033[0m for VBA macro emulation: (https://github.com/decalage2/ViperMonkey)\n\033[95mEvilClippy\033[0mfor removing passwords from VBA projects: (https://github.com/outflanknl/EvilClippy)")

            elif '7-zip archive data' or 'zip archive' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mzipdump.py\033[0m for extracting zip archive components: (https://github.com/DidierStevens/DidierStevensSuite/blob/master/zipdump.py)")  

            elif 'gzip compressed data' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95mgzip\033[0m for unzipping contents: (https://www.gnu.org/software/gzip/)\n\033[95mzcat\033[0m for analyzing file contents: (https://linux.die.net/man/1/zcat)\n\033[95m7-zip\033[0m for unzipping and analyzing contents: (https://www.7-zip.org/download.html)")  

            elif 'iso' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95m7-zip\033[0m for unzipping and analyzing contents: (https://www.7-zip.org/download.html)\n\033[95misoinfo\033[0m for listing and extracting contents: (https://linux.die.net/man/8/isoinfo)\n\033[95mount\033[0m - bash command to mount the ISO as a disk (https://man7.org/linux/man-pages/man8/mount.8.html)") 

            elif 'windows shortcut' in file_type.lower():
                print("\n\033[1m[ANALYSIS RECOMMENDATIONS]\033[0m\n\033[95m7-zip\033[0mLECmd\033[0m LNK Explorer (command-line tool) by Eric Zimmerman: (https://github.com/EricZimmerman/LECmd)")
                                                               
    except Exception as e:
        print(f"\033[1mError -- Unknown file type.\033[0m Try using TrID (although it will provide a little less information).\n\nYou can download it here: \nhttps://mark0.net/soft-trid-e.html")

def check_and_install_dependencies():
    required_packages = ['argparse', 'magic', 'os', 'sys', 'importlib', 'subprocess']
    missing_packages = False

    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            print(f"The package '{package}' is not installed.")
            install = input(f"Pointman requires the Python library {YELLOW}'{package}'{RESET} to work correctly. {YELLOW}{package}{RESET} is not currently installed - do you want to install it? [y/n]").strip().lower()
            if install == 'y':
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                print(f"The package {YELLOW}'{package}'{RESET} has been installed.")
                missing_packages = True
            else:
                print(f"The package {YELLOW}'{package}'{RESET} was not installed. The script will not work correctly without it.")
    if not missing_packages:
        print(f"\033[92m\u2714 Necessary packages are installed...{RESET} \n\n")

def main():
    # Check and install dependencies if necessary
    check_and_install_dependencies()

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Welcome to Pointman, the advanced file identification program that is designed to help malware REs and forensic analysts.")
    parser.add_argument("-f", dest="file", help="The path to the file to be identified.", required=True)
    parser.add_argument("-v", dest="verbose", action='store_true', help="Verbose mode - Use this flag to receive extra information for malware analysis, forensics, etc.")
    args = parser.parse_args()

    # Identify the file type
    identify_file(args.file, args.verbose)

if __name__ == "__main__":
    setup_alias()
    main()
