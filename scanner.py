#!/usr/bin/env python3

import tinker_functions as tkfunc
import os
import time
import shutil

LOG_FILE = "scanner_log.txt"
TOSCAN = "toscan/"
APPROVED = "approved/"
QUARANTINED = "quarantined/"
EXTENSIONS = (".tar", ".tar.gz", ".zip", ".bz2")
BADSITES_FILE = "sites_to_scanfor.txt"
REST_TIME = 30

with open(LOG_FILE,'w') as file:
    timestamp = tkfunc.get_time_string()
    file.write(f"Scanner Starting at {timestamp}")

while True:
    if time.localtime().tm_min % 5 == 0: # if the minute is multiple of 5 (example 10:05 pm or 7:00am)
        tkfunc.reload_website_file() 
    
    dir_content = os.listdir(TOSCAN)

    if dir_content:
        for item in dir_content:
            if item.endswith(EXTENSIONS):
                file = TOSCAN+item
                log = tkfunc.analyze_archive(file,BADSITES_FILE)
                if log.reason_trigger_dict:
                    shutil.move(file, QUARANTINED)

                    with open(QUARANTINED + item + ".reason",'a') as r_file:
                        for key,value in log.reason_trigger_dict.items():
                            r_file.write(f"\n\n{file}\n{key}\n{value}")

                    with open(LOG_FILE,'a') as l_file:
                        timestamp = tkfunc.get_time_string()
                        l_file.write(f"\n\t{timestamp}, {file}, QUARANTINED")

                else:
                    shutil.move(file, APPROVED)
                    with open(LOG_FILE,'a') as l_file:
                        timestamp = tkfunc.get_time_string()
                        l_file.write(f"\n\t{timestamp}, {file}, APPROVED")
    else:
        time.sleep(REST_TIME)
    




    




