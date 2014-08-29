vt-to-maec
==========

VirusTotal fetcher and VirusTotal report --> MAEC XML Converter Utility  
v0.95 BETA - Updated 08/29/2014  

Copyright (c) 2014 The MITRE Corporation  
BY USING THE VIRUSTOTAL TO MAEC SCRIPT AND MODULE, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE SCRIPT.  
See `terms.txt` for terms of use.

**MAEC** - http://maec.mitre.org  
**VirusTotal** - https://www.virustotal.com

Given a list of MD5 hashes and/or file paths, this script fetches the VirusTotal reports for each file and outputs MAEC data about each file.  
Compatible with MAEC Schema v4.1 & CybOX 2.1

Requirements:

* python-maec >= v4.1.0.7
* python-cybox >= v2.1.0.6
* Before you can run the `vt_to_maec.py` script for the first time, you must get a VirusTotal API key from https://www.virustotal.com and use it as the `API_KEY` variable at the top of the script.

Usage: `python vt_to_maec.py [-j] [-h MD5_HASH ...] [-f FILEPATH ...] [-o FILEPATH]`

Use the `-h` option followed by up to four MD5 arguments and/or the `-f` option followed by up to four paths to malware samples.

* `-h`: starts the list of MD5 hashes
* `-f`: starts the list of malware sample paths
* `-o`: specifies the output file path
* `-j`: specifies JSON output instead of default XML

The VirusTotal service allows a maximum of 4 samples per submission.

The `virustotal_maec_packager.py` file can be used as a stand-alone module that exposes the following functions:

* `file_to_md5(filepath)`
  * Returns a hash of the file at `filepath` as an MD5 hex string.
* `vt_report_from_md5(input_md5, api_key, proxies=None)`
  * Accepts a string of comma-separated MD5 hashes or a list of MD5 strings. Fetches reports from VirusTotal (using the MD5 values and the specified VirusTotal API key) and returns a dictionary or list of dictionaries built from the VirusTotal report JSON. Accepts an optional dictionary of proxies like `{ "http": ..., "https": ... }`. The `api_key` parameter is required unless the module-wide variable `API_KEY` has been set.
* `vt_report_to_maec_package(vt_report)`
  * Accepts a VirusTotal report (as a Python structure) and returns a corresponding MAEC Package object from `python-maec`.
