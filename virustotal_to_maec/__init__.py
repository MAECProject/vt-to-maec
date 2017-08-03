# Copyright (c) 2015, The MITRE Corporation. All rights reserved.

#BY USING THE VIRSUTOTAL MAEC PACKER MODULE SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE
#OF THE TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO
#NOT USE THE VIRSUTOTAL MAEC PACKER MODULE.

#For more information, please refer to the LICENSE.txt file.

#VirusTotal to MAEC Standalone Package
#Updated 09/08/2014 for MAEC v4.1 and CybOX v2.1

#Standalone package for fetching VirusTotal results and converting them to MAEC packages
import hashlib
import json
from maec.package.package import Package
import virustotal_maec_packager as vtpack

__version__ = "0.11"

proxies = {}
api_key = ""
    
def generate_package_from_report_filepath(input_path, options = None):
    """Take a file path to a VirusTotal report and return a MAEC package object."""
    try:
        vt_file = open(input_path, 'r')
        vt_dict = json.load(vt_file)
    except:
        print("\nError: Error in parsing input file. Please check to ensure that it is valid JSON.")
        return
    
    return vtpack.vt_report_to_maec_package(vt_dict, options)

def generate_package_from_binary_filepath(input_path, options = None):
    """Take a file path to a binary file, try to look up its VirusTotal report by MD5, 
       and return a MAEC package object if a report is found."""
    # create MD5
    blocksize = 65536
    fd = open(input_path, "rb")
    hasher = hashlib.md5()
    buf = fd.read(blocksize)

    while len(buf) > 0:
        hasher.update(buf)
        buf = fd.read(blocksize)
    
    return generate_package_from_md5(hasher.hexdigest())

def generate_package_from_md5(input_md5, options = None):
    """Take an MD5 string, try to look up its VirusTotal report, 
    and return a MAEC package object if a report is found."""
    return vtpack.vt_report_to_maec_package(
                                            vtpack.vt_report_from_md5(input_md5, api_key, proxies),
                                            options
                                            )

def generate_package_from_report_string(input_string, options = None):
    """Take a VirusTotal report as a string and return a MAEC package object."""
    vt_dict = json.loads(input_string)
    return vtpack.vt_report_to_maec_package(vt_dict, options)

def set_proxies(proxy_dict={}):
    """Take a dictionary of proxies to use for network fetches, 
    where keys are protocol names and values are proxy addresses; 
    e.g., { 'http':'http://example.com:80' }."""
    global proxies
    proxies = proxy_dict
    
def set_api_key(new_api_key):
    """Set the API key used by the module"""
    global api_key
    api_key = new_api_key
