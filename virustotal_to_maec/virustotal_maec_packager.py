# Copyright (c) 2015, The MITRE Corporation. All rights reserved.

#BY USING THE VIRSUTOTAL MAEC PACKER MODULE SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE
#OF THE TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO
#NOT USE THE VIRSUTOTAL MAEC PACKER MODULE.

#For more information, please refer to the LICENSE.txt file.

#VirusTotal MAEC Packager
#Updated 09/08/2014 for MAEC v4.1 and CybOX v2.1

#Standalone module for fetching VirusTotal results and converting them to MAEC packages

"""VirusTotal fetcher and VirusTotal-to-MAEC conversion module"""

import mixbox.idgen
import requests
import hashlib
import json
import sys
from maec.misc.exceptions import APIKeyException, LookupNotFoundException

API_KEY = None

def file_to_md5(path, blocksize=65536):
    """Return a hash of the file at filepath as an MD5 hex string."""
    fd = open(path, "rb")
    hasher = hashlib.md5()
    buf = fd.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = fd.read(blocksize)
    return hasher.hexdigest()
    

def vt_report_from_md5(input_md5, api_key=None, proxies=None):
    """Accept a string of comma-separated MD5 hashes or a list of MD5 strings to use in fetching a report to VirusTotal.
    Return a dictionary or list of dictionaries based on the fetched report's JSON.
    Requires a VirusTotal API key as the second argument. Optionally accepts a dictionary of proxy settings ({ "http": ... })."""
    global API_KEY
    api_key = api_key or API_KEY
    
    # if the module var is not set and 
    if api_key is None:
        raise APIKeyException("No VirusTotal API key set. Supply it as an argument or set the API_KEY module variable")
        
    if type(input_md5) == list:
        input_md5 = ",".join(input_md5)
        
    parameters = { "resource": input_md5, "apikey": api_key }
    response = requests.get("http://www.virustotal.com/vtapi/v2/file/report", params=parameters, proxies=proxies)
    
    if response.text == "":
        raise APIKeyException("Empty VirusTotal response. Your API key may be incorrect.")
    if response.text == "[]":
        raise LookupNotFoundException("VirusTotal has never seen a file with MD5 " + input_md5)

    return response.json()


#in this version, the function returns a mere dictionary
def vt_report_to_maec_package(vt_report_input, options = None):
   
   #creating package structure and inserting all package level fields
    package = {}
    package['id'] = mixbox.idgen.create_id(prefix="package").split(":")[1]
    package['schema_version'] = "5.0"
    package['malware_instances'] = []
    package['objects'] = {}
 
    # if only one result, make it a list of one result
    if type(vt_report_input) != list:
        vt_report_list = [vt_report_input]
    else:
        vt_report_list = vt_report_input

    for idx, vt_report in enumerate(vt_report_list):
        # if VirusTotal has never seen this MD5
        if vt_report['response_code'] == 0:
            sys.stderr.write("WARNING: Skipping file #" + str(idx+1) + " (" + vt_report["resource"] + "); this MD5 is unknown to VirusTotal\n")
            sys.stderr.flush();
            continue
        if vt_report["response_code"] == -1:
            sys.stderr.write("WARNING: VirusTotal had an unexpected error on file #" + str(idx+1) + " (" + vt_report["resource"] + "): " +
                             vt_report.get("verbose_message", "no message provided") + "\n")
            sys.stderr.flush();
            continue
            
        #create instance object reference ID for the malware instance
        instance_object_ref = mixbox.idgen.create_id(prefix="malware_instance_object").split(":")[1]

        #add malware instance to package
        package['malware_instances'].append(
            {
                'id': mixbox.idgen.create_id(prefix="malware_instance").split(":")[1],
                'instance_object_ref': [ instance_object_ref ]
            })

        #create cyber observable object dictionary - all AV classifications are nested under here
        package['objects'][instance_object_ref] = {
            'type':'file',
            'hashes':{
                'MD5': vt_report['md5'],
                'SHA-1': vt_report['sha1'],
                'SHA-256': vt_report['sha256']
            },
            'extended_properties':{
                'x-maec-avclass': []
            }
        }

        #just getting a shorter reference to use
        maec_av = package['objects'][instance_object_ref]['extended_properties']['x-maec-avclass']

        #iterate through all ofg VT results, add classifications to cyber observable object
        for k,v in vt_report['scans'].items():
            tmp = {}
            tmp['classification_name'] = v['result']
            tmp['scan_date'] = vt_report['scan_date']
            tmp['is_detected'] = v['detected']
            tmp['av_name'] = k
            tmp['av_vendor'] = k
            tmp['av_engine_version'] = v['version']
            tmp['av_definition_version'] = v['update']

            maec_av.append(tmp)
       
    try:
        json.loads(json.dumps(package))       
    except ValueError, e:
        sys.stderr.write("WARNING: MAEC package dictionary created from Virus Total results was NOT verified as proper json format.")
        sys.stderr.write("\n"+ str(e) + "\n")
        sys.stderr.flush();

    return package
