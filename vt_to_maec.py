#****************************************************#
#                                                    #
#      VirusTotal -> MAEC XML Script                 #
#                                                    #
#      Copyright (c) 2015, The MITRE Corporation     #
#                                                    #
#****************************************************#

#BY USING THE VIRUSTOTAL TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE VIRUSTOTAL
#TO MAEC SCRIPT.

#For more information, please refer to the terms.txt file.

#VirusTotal Converter Script
#Copyright 2015, MITRE Corp
#v0.11 - BETA
#Updated 09/08/2014 for MAEC v4.1 and CybOX v2.1

"""VirusTotal fetcher and VirusTotal report --> MAEC XML Converter Utility
v0.10 BETA // Supports MAEC v4.1 and CybOX v2.1

IMPORTANT: Before use, you MUST edit this script to contain your VirusTotal API key (in the API_KEY variable).

Given a list of MD5 hashes and/or file paths, this script fetches the files from VirusTotal
and outputs MAEC data about each file.

Usage: python vt_to_maec.py [--hash] input output
"""

#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!
# Before you can use this script, you must supply a VirusTotal API key
API_KEY = "REPLACE THIS STRING WITH AN API KEY FROM https://www.virustotal.com"
#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#!#! 

import virustotal_to_maec.virustotal_maec_packager as vtp
import sys
import virustotal_to_maec
import argparse
import json
from maec.misc.options import ScriptOptions

proxies = {
        #"http":"http://example.com:80",
        #"https":"http://example.com:80"
    }

parser = argparse.ArgumentParser(description="VirusTotal to MAEC Translator")
parser.add_argument("input", help="the MD5 hash or path of the input binary file")
parser.add_argument("output", help="the name of the file to which the MAEC XML output will be written")
parser.add_argument("--md5", "--hash", help="indicates input is an MD5 hash of the file to be fetched and analyzed", action="store_true", default=False)
parser.add_argument("--verbose", "-v", help="enable verbose error output mode", action="store_true", default=False)
parser.add_argument("--deduplicate", "-dd", help="deduplicate the MAEC output (Objects only)", action="store_true", default=False)
parser.add_argument("--normalize", "-n", help="normalize the MAEC output (Objects only)", action="store_true", default=False)
parser.add_argument("--dereference", "-dr", help="dereference the MAEC output (Objects only)", action="store_true", default=False)
args = parser.parse_args()

# Build up the options instance based on the command-line input
options = ScriptOptions()
options.deduplicate_bundles = args.deduplicate
options.normalize_bundles = args.normalize
options.dereference_bundles = args.dereference

virustotal_to_maec.set_api_key(API_KEY)
virustotal_to_maec.set_proxies(proxies)

# fetch VT report and generate Package object
try:
    if args.md5:
        package_result = virustotal_to_maec.generate_package_from_md5(args.input, options)
    else:
        package_result = virustotal_to_maec.generate_package_from_binary_filepath(args.input, options)
except vtp.APIKeyException as ex:
    sys.stderr.write("VirusTotal API request failed. You must edit this script with your VirusTotal API key in the API_KEY variable.")
    sys.exit();

package_result['description'] = "Created by VirusTotal to MAEC (http://github.com/MAECProject/vt-to-maec)"

with open(args.output, 'w') as fp: 
	json.dump(package_result, fp)

print "Wrote output to " + args.output
