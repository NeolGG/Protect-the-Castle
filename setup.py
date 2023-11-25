#!/usr/bin/env python3

import os

ARCHIVE = "archive/"
TOSCAN = "toscan/"
APPROVED = "approved/"
QUARANTINED = "quarantined/"

dirs_to_make = [ARCHIVE,TOSCAN,APPROVED,QUARANTINED]

for directory in dirs_to_make:
    try:
        os.makedirs(directory)
    except Exception as e:
        continue

