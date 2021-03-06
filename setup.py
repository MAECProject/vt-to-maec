# Copyright (c) 2018, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from os.path import abspath, dirname, join

from setuptools import find_packages, setup

INIT_FILE = join(dirname(abspath(__file__)), 'virustotal_to_maec', '__init__.py')


def get_version():
    with open(INIT_FILE) as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


with open('README.rst') as f:
    readme = f.read()


setup(
    name="virustotal_to_maec",
    version=get_version(),
    author="MAEC Project",
    author_email="maec@mitre.org",
    description="An package for parsing VirusTotal reports into MAEC documents.",
    long_description=readme,
    url="http://maec.mitre.org",
    packages=find_packages(),
    install_requires=['maec>=4.1.0.9,<4.1.1.0', 'cybox>=2.1.0.8,<2.1.1.0'],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ]
)
