""" Copyright (c) 2018, The MITRE Corporation. All rights reserved.

BY USING THE VIRSUTOTAL MAEC PACKER MODULE SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE
OF THE TERMS AND CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO
NOT USE THE VIRSUTOTAL MAEC PACKER MODULE.

For more information, please refer to the LICENSE.txt file.

VirusTotal MAEC Packager
Updated 04/25/2018 for MAEC v5.0

Standalone module for fetching VirusTotal results and converting them to MAEC packages
"""

import hashlib
import json
import sys

import mixbox.idgen
import requests
from maec.misc.exceptions import APIKeyException, LookupNotFoundException

API_KEY = None


def file_to_md5(path, blocksize=65536):
    """Return a hash of the file at filepath as an MD5 hex string."""
    fd = open(path, 'rb')
    hasher = hashlib.md5()
    buf = fd.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = fd.read(blocksize)
    return hasher.hexdigest()


def vt_report_from_md5(input_md5, api_key=None, proxies=None):
    """Accept a string of comma-separated MD5 hashes or a list of
    MD5 strings to use in fetching a report to VirusTotal.
    Return a dictionary or list of dictionaries based on the fetched
    report's JSON. Requires a VirusTotal API key as the second argument.
    Optionally accepts a dictionary of proxy settings ({ "http": ... })."""

    global API_KEY
    api_key = api_key or API_KEY

    # if the module var is not set and
    if api_key is None:
        raise APIKeyException("No VirusTotal API key set. Supply it as an"
                              " argument or set the API_KEY module variable")

    if type(input_md5) == list:
        input_md5 = ",".join(input_md5)

    parameters = {"resource": input_md5, "apikey": api_key}

    response = requests.get("http://www.virustotal.com/vtapi/v2/file/report",
                            params=parameters,
                            proxies=proxies)

    if response.text == "":
        raise APIKeyException("Empty VirusTotal response. Your API key may be"
                              " incorrect.")
    if response.text == "[]":
        raise LookupNotFoundException("VirusTotal has never seen a file with"
                                      " MD5 {0}".format(input_md5))

    return response.json()


def vt_report_to_maec_package(vt_report_input):
    """Virus Total report to MAEC 5.0 Package in JSON"""

    # creating package structure and inserting all package level fields
    package = {}
    package["type"] = "package"
    package["id"] = mixbox.idgen.create_id(prefix="package-").split(":")[1]
    package["schema_version"] = "5.0"
    package["maec_objects"] = []
    package["observable_objects"] = {}

    if not isinstance(vt_report_input, list):
        # make input an interable
        vt_report_input = [vt_report_input]

    for idx, vt_report in enumerate(vt_report_input):
        # VT has never seen this MD5
        if vt_report["response_code"] == 0:
            sys.stderr.write("WARNING: Skipping file #{0} ({1}) - this MD5 is unknown to VirusTotal\n".format(
                             str(idx + 1),
                             vt_report["resource"]))
            sys.stderr.flush()
            continue

        if vt_report["response_code"] == -1:
            # VT error
            sys.stderr.write("WARNING: VirusTotal had an error on file #{0} ({1}): {2}\n".format(
                             str(idx + 1),
                             vt_report["resource"],
                             vt_report.get("verbose_message", "no message provided")))
            sys.stderr.flush()
            continue

        # create instance object reference ID for the malware instance
        instance_object_ref = '0'

        # add malware instance to package
        package["maec_objects"].append(
            {
                "type": "malware-instance",
                "id": mixbox.idgen.create_id(prefix="malware-instance-").split(":")[1],
                "instance_object_refs": [instance_object_ref],
                "analysis_metadata": [
                    {
                        "is_automated": True,
                        "analysis_type": "static",
                        "description": "Created by VirusTotal to MAEC (http://github.com/MAECProject/vt-to-maec)"
                    }
                ]
            })

        # create cyber observable object dictionary - all AV classifications are nested under here
        obsv_obj = package["observable_objects"][instance_object_ref] = {}
        obsv_obj["type"] = "file"
        obsv_obj["hashes"] = {
            "MD5": vt_report["md5"],
            "SHA-1": vt_report["sha1"],
            "SHA-256": vt_report["sha256"]
        }
        obsv_obj["extensions"] = {
            "x-maec-avclass": []
        }

        # just a shorter reference to use
        maec_av = package["observable_objects"][instance_object_ref]["extensions"]["x-maec-avclass"]

        # iterate through all ofg VT results, add classifications to cyber observable object
        for k, v in vt_report["scans"].iteritems():
            tmp = {}
            tmp["classification_name"] = v["result"]
            tmp["scan_date"] = vt_report["scan_date"]
            tmp["is_detected"] = v["detected"]
            tmp["av_name"] = k
            tmp["av_vendor"] = k
            tmp["av_engine_version"] = v["version"]
            tmp["av_definition_version"] = v["update"]

            maec_av.append(tmp)

    try:
        json.loads(json.dumps(package))
    except Exception as e:
        sys.stderr.write("WARNING: MAEC package created from Virus Total results was NOT verified as proper JSON.")
        sys.stderr.write(str(e))
        sys.stderr.flush()

    return package
