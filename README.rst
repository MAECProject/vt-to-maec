vt-to-maec
==========

VirusTotal fetcher and VirusTotal report --> MAEC JSON Converter Utility
v0.1 Updated 04/25/2018

Copyright (c) 2018 The MITRE Corporation
BY USING THE VIRUSTOTAL TO MAEC SCRIPT AND MODULE, YOU SIGNIFY YOUR
ACCEPTANCE OF THE TERMS AND CONDITIONS OF USE. IF YOU DO NOT AGREE TO
THESE TERMS, DO NOT USE THE SCRIPT.
See ``terms.txt`` for terms of use.

**IMPORTANT:** Before use, you must edit this script to contain your
VirusTotal API key (in the ``API_KEY`` variable in ``vt_to_maec``).

Given a list of MD5 hashes and/or file paths, this script fetches the
VirusTotal reports for each file and outputs MAEC data about each file.

Compatible with MAEC Schema v5.0

* MAEC - http://maecproject.github.io/
* VirusTotal - https://www.virustotal.com

Requirements
============

-  Before you can run the ``vt_to_maec.py`` script for the first time,
   you must get a VirusTotal API key from https://www.virustotal.com and
   use it as the ``API_KEY`` variable at the top of the script.

Usage
=====

``python vt_to_maec.py <input binary file path or MD5> [--md5] [--verbose]``

- ``--md5``, ``--hash``: specifies that the input is an MD5 hash rather
than a binary file path.
- ``--deduplicate``, ``-dd``: deduplicate objects in MAEC output
- ``--dereference``, ``-dr``: dereference the MAEC output
- ``--normalize``, ``-n``: normalize the MAEC output

Standalone Module
=================

The ``virus_total_to_maec`` package exposes several helper functions:

-  ``generate_package_from_binary_filepath`` - given an filepath, return
   a python-maec Pacakge object
-  ``generate_package_from_md5`` - given an MD5 string, return a
   python-maec Pacakge object
-  ``generate_package_from_report_string`` - given a VirusTotal JSON
   report, return a python-maec Pacakge object
-  ``set_proxies`` - optionally called to supply proxy information to
   the package; supplied as a dictionary like
   ``{ "http": "http://example.com:80", ... }``
-  ``set_api_key`` - called to supply an API key string to the module

About MAEC
==========

Malware Attribute Enumeration and Characterization (MAEC™) is a standardized language for sharing structured information about malware based upon attributes such as behaviors, artifacts, and attack patterns.

The goal of the MAEC (pronounced "mike") effort is to provide a basis for transforming malware research and response. MAEC aims to eliminate the ambiguity and inaccuracy that currently exists in malware descriptions and to reduce reliance on signatures. In this way, MAEC seeks to improve human-to-human, human-to-tool, tool-to-tool, and tool-to-human communication about malware; reduce potential duplication of malware analysis efforts by researchers; and allow for the faster development of countermeasures by enabling the ability to leverage responses to previously observed malware instances. The MAEC Language enables correlation, integration, and automation.

Please visit the `MAEC website <https://maecproject.github.io/>`_ for more information about the MAEC Language.

Getting Help
============

Join the public `MAEC Community Email Discussion List <https://maec.mitre.org/community/discussionlist.html>`_.

Email the MAEC Developers at maec@mitre.org.
