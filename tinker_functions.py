import tarfile
import zipfile
import bz2
import os
import requests
import re
import subprocess
import shutil
import time
from dataclasses import dataclass, field
from typing import Dict,List

@dataclass
class Log:
    filename: str
    reason_trigger_dict: Dict[str,List[str]] = field(default_factory=dict)
    
BADSITES_FILE = "sites_to_scanfor.txt"
EXTRACTION_LOCATION = "archive/"
TOSCAN = "toscan/"

# Extraction Functions
def extract_tar(path: str,destin: str):
    with tarfile.open(path,'r') as file:
        file.extractall(destin)

def extract_tar_gz(path: str,destin: str):
    with tarfile.open(path,'r:gz') as file:
        file.extractall(destin)

def extract_zip(path: str,destin: str):
    with zipfile.ZipFile(path,'r') as file:
        file.extractall(destin)

def extract_bz2(path: str,destin: str):
    output = path.split('/')[-1]
    with bz2.open(path,'rb') as file:
        content = file.read()
        with open(destin + output,'wb') as new_file:
            new_file.write(content)

def extract_archive(arhive: str,destination: str): #exracts all the files into destination folde
    if arhive.endswith('.tar'):
        extract_tar(arhive,destination)
    elif arhive.endswith('.tar.gz'):
        extract_tar_gz(arhive,destination)
    elif arhive.endswith('.zip'):
        extract_zip(arhive,destination)
    elif arhive.endswith('.bz2'):
        extract_bz2(arhive,destination)
    else:
        print("File type not supported, support only for .tar, .tar.gz, .zip, and .bz2")
        return 1
    return 0

# Website functions
def reload_website_file():
    response = requests.get('https://urlhaus.abuse.ch/downloads/text_online/')

    if response.status_code == 200:
        with open(BADSITES_FILE, "wb") as file:
            file.write(response.content)
        print("Downloaded successfully.")
    else:
        print(f"Failed to download. Status code: {response.status_code}")

# Scanner Functions
def load_file_as_set(file_name: str):
    if not os.path.exists(file_name):
        print(f"{file_name} does not exist")
        return None
    else:
        with open(file_name, 'r') as file:
            file_set = set(line.strip() for line in file)
    return file_set

def scan_for_badsites(file_name: str, badsites_set: set):
    if not os.path.exists(file_name):
        print(f"{file_name} does not exist")
        return None
    if not badsites_set:
        print("Set is empty")
        return None
    
    bad_urls_found = list()

    with open(file_name, 'r') as file:
        for line in file:
            if any(site in line for site in badsites_set):
                bad_urls_found.append(line.strip())
    
    return bad_urls_found

def is_credit_card(card_number: str):
    card_number = card_number.replace(" ", "")[::-1]

    total = 0
    even = False

    for digit in card_number:
        digit = int(digit)
        if even:
            digit *= 2
            if digit > 9:
                digit -= 9
        
        total += digit
        even = not even
    
    return total % 10 == 0

def scan_for_sensitive_info(file_name :str):
    phone_regex = r'(\(\d{3}\)\s*|\d{3}-)\d{3}-\d{4}'
    card_regex  = r'(\d{4}\s*\d{4}\s*\d{4}\s*\d{4}|\d{16})'
    ssn_regex = r'\b\d{3}-\d{2}-\d{4}\b'

    if not os.path.exists(file_name):
        print(f"{file_name} does not exist")
        return None
    
    sensitive_info_found = list()

    try:
        with open(file_name, 'r') as file:
            for line in file:
                sensitive_info_found.extend(re.findall(phone_regex, line))
                for item in re.findall(card_regex,line):
                    if is_credit_card(item):
                        sensitive_info_found.append(item)
                sensitive_info_found.extend(re.findall(ssn_regex, line))
    except Exception as e:
        print(f"Error: {e}")
        return None
    
    return sensitive_info_found

def clear_directory(directory):
    try:
        subprocess.run(['rm', '-fr', directory], check=True)
        os.mkdir(directory)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")

# Analyze Functions

def analyze_archive(archive_name: str,badsite_file: str):
    archive_log = Log(archive_name) 
    destination = EXTRACTION_LOCATION 
    
    clear_directory(destination)

    urls_found = []
    info_found = []
    EA_FLAG = extract_archive(archive_name,destination)

    files_to_scan = os.listdir(destination)
    badsites_set = load_file_as_set(badsite_file)

    for file in files_to_scan:
        file = os.path.join(destination,file)

        if os.path.isfile(file):
            try:
                urls_found.extend(scan_for_badsites(file,badsites_set))
                info_found.extend(scan_for_sensitive_info(file))
            except Exception as e:
                print(f"Error: {e}")
        else:
            try:
                shutil.move(file,TOSCAN)
            except shutil.Error as e:
                if "already exists" in str(e): #if directory is already in the toscan folder
                    shutil.move(file,TOSCAN + os.path.basename(file) + time.strftime("%Y%m%d_%H%M%S", time.localtime()))
                else:
                    print(f"Error: {e}")

    if urls_found or info_found or EA_FLAG:
        if urls_found:
            archive_log.reason_trigger_dict["MALICIOUSURL"] = urls_found
        if info_found:
            archive_log.reason_trigger_dict["SENSITIVE"] = info_found
        if EA_FLAG:
            archive_log.reason_trigger_dict["CANNOTEXTRACT"] = None

    return archive_log

# Time Functions

def get_time_string():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())