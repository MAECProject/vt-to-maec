#****************************************************#
#                                                    #
#      VirusTotal -> MAEC XML Script                 #
#                                                    #
#      Copyright (c) 2014, The MITRE Corporation     #
#                                                    #
#****************************************************#

#BY USING THE VIRSUTOTAL TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE VIRSUTOTAL
#TO MAEC SCRIPT.

#For more information, please refer to the terms.txt file.

#VirusTotal Converter Script
#Copyright 2014, MITRE Corp
#v0.95 - BETA
#Updated 08/29/2014 for MAEC v4.1 and CybOX v2.1

"""VirusTotal fetcher and VirusTotal report --> MAEC XML Converter Utility
v0.95 BETA // Supports MAEC v4.1 and CybOX v2.1

Given a list of MD5 hashes and/or file paths, this script fetches the files from VirusTotal
and outputs MAEC data about each file.

You must enter your VirusTotal API key into the script before use.

Usage: python vt_to_maec.py [-j] [-h MD5_HASH ...] [-f FILEPATH ...] [-o FILEPATH]

Use the -h option followed by up to four MD5 arguments
and/or
Use the -f option followed by up to four paths to malware samples

-h: starts the list of MD5 hashes
-f: starts the list of malware sample paths
-o: specifies the output file path
-j: specifies JSON output instead of default XML

The VirusTotal service allows a maximum of 4 samples per submission."""


#############################################################################
#! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! !

# Before you can use this script, you must supply a VirusTotal API key
API_KEY = "REPLACE THIS STRING WITH AN API KEY FROM https://www.virustotal.com"

#! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! 
#############################################################################

import virustotal_maec_packager as vtp
import sys

def usage():
    print USAGE_TEXT

USAGE_TEXT = __doc__

proxies = {
#           "http": "http://example.com:80",
#           "https": "http://example.com:80",
           }

md5_list = []
read_mode = None
write_mode = "xml"
output_path = None
has_input = False

# read and process command args
args = sys.argv[1:]

if len(args) < 2:
    usage()
    sys.exit(1)
    
for i in range(0,len(args)):
    if args[i] == '-f':
        read_mode = "file"
    elif args[i] == '-h':
        read_mode = "hash"
    elif args[i] == '-o':
        read_mode = "output"
    elif args[i] == '-j':
        write_mode = "json"
    else:
        if read_mode == "hash":
            md5_list.append(args[i])
        elif read_mode == "file":
            md5_list.append(vtp.file_to_md5(args[i]))
        elif read_mode == "output":
            output_path = args[i]
            read_mode = ""
        else:
            usage()
            sys.exit(1)
        has_input = True

# no hashes or files specified
if not has_input:
    usage()
    sys.exit(1)

# too many targets; VT only allows 4
if len(md5_list) > 4:
    sys.stderr.write("ERROR: cannot specify more than 4 inputs per run\n")
    sys.stderr.flush()
    sys.exit(1)

# fetch VT report and generate Package object
vt_report = vtp.vt_report_from_md5(md5_list, API_KEY, proxies=proxies)
package_result = vtp.vt_report_to_maec_package(vt_report)

# generate output
if write_mode == "xml":
    output_string = package_result.to_xml(True, {"https://github.com/MAECProject/vt-to-maec": "VirusTotalToMAEC"}, True)
elif write_mode == "json":
    output_string = package_result.to_json()

# push output to file or stdout
if output_path is not None:
    fd = open(output_path, "w")
    fd.write(output_string)
    fd.close()
else:
    print output_string
    