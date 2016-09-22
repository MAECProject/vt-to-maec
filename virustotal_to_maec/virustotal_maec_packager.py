# Copyright (c) 2015, The MITRE Corporation. All rights reserved.

#BY USING THE VIRSUTOTAL MAEC PACKER MODULE SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE
#OF THE TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO
#NOT USE THE VIRSUTOTAL MAEC PACKER MODULE.

#For more information, please refer to the LICENSE.txt file.

#VirusTotal MAEC Packager
#Updated 09/08/2014 for MAEC v4.1 and CybOX v2.1

#Standalone module for fetching VirusTotal results and converting them to MAEC packages

"""VirusTotal fetcher and VirusTotal-to-MAEC conversion module"""

import maec.utils
import mixbox.idgen
from maec.bundle.bundle import Bundle
from maec.package.package import Package
from maec.bundle.av_classification import AVClassification
from maec.package.analysis import Analysis
from maec.package.malware_subject import MalwareSubject
from cybox.core.object import Object
from cybox.common.tools import ToolInformation
from cybox.utils import Namespace
import requests
import hashlib
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

def vt_report_to_maec_package(vt_report_input, options = None):
    """Accept a VirusTotal report (as a Python structure) and return a corresponding MAEC Package API object."""
    NS = Namespace("https://github.com/MAECProject/vt-to-maec", "VirusTotalToMAEC")
    mixbox.idgen.set_id_namespace(NS)
    
    package = Package()

    # if only one result, make it a list of one result
    if type(vt_report_input) != list:
        vt_report_list = [vt_report_input]
    else:
        vt_report_list = vt_report_input

    for idx, vt_report in enumerate(vt_report_list):
        # if VirusTotal has never seen this MD5
        if vt_report["response_code"] == 0:
            sys.stderr.write("WARNING: Skipping file #" + str(idx+1) + " (" + vt_report["resource"] + "); this MD5 is unknown to VirusTotal\n")
            sys.stderr.flush();
            continue
        if vt_report["response_code"] == -1:
            sys.stderr.write("WARNING: VirusTotal had an unexpected error on file #" + str(idx+1) + " (" + vt_report["resource"] + "): " +
                             vt_report.get("verbose_message", "no message provided") + "\n")
            sys.stderr.flush();
            continue
        
        malware_subject = MalwareSubject()
        
        # create the file object and add hashes
        file_dict = {}
        file_dict['xsi:type'] = 'WindowsExecutableFileObjectType'
        file_dict['hashes'] = [
            {'type' : 'MD5', 'simple_hash_value': vt_report["md5"] },
            {'type' : 'SHA1', 'simple_hash_value': vt_report["sha1"] },
            {'type' : 'SHA256', 'simple_hash_value': vt_report["sha256"] }
        ]
        
        # set the object as the defined object
        object_dict = {}
        object_dict['id'] = maec.utils.idgen.create_id(prefix="object")
        object_dict['properties'] = file_dict
        
        # bind the object to the malware subject object
        malware_subject.set_malware_instance_object_attributes(Object.from_dict(object_dict))
        
        # create the analysis and add it to the subject
        analysis = Analysis()
        analysis.type_ = 'triage'
        analysis.method = 'static'
        analysis.complete_datetime = vt_report["scan_date"].replace(" ", "T")
        analysis.add_tool(ToolInformation.from_dict({'id' : maec.utils.idgen.create_id(prefix="tool"),
                           'vendor' : 'VirusTotal',
                           'name' : 'VirusTotal' }))
        malware_subject.add_analysis(analysis)
        
        bundle_obj = Bundle()
        
        for vendor, scan in vt_report["scans"].items():
            if scan["result"] is not None:
                bundle_obj.add_av_classification(AVClassification.from_dict({ 'classification_name' : scan["result"], 'vendor' : vendor }))
        
        # add bundle to subject, bundle to analysis, and subject to package
        malware_subject.add_findings_bundle(bundle_obj)
        analysis.set_findings_bundle(bundle_obj.id_)
        package.add_malware_subject(malware_subject)
        
        package.__input_namespaces__["https://github.com/MAECProject/vt-to-maec"] = "VirusTotalToMAEC"
        
        if options:
            if options.normalize_bundles:
                malware_subject.normalize_bundles()
            if options.deduplicate_bundles:
                malware_subject.deduplicate_bundles()
            if options.dereference_bundles:
                malware_subject.dereference_bundles()
        
    return package
