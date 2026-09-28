# Week 4 – CVE Vulnerability Information Tool

## Overview

The CVE Vulnerability Information Tool is a Python-based defensive security tool that retrieves publicly available vulnerability information from the National Vulnerability Database (NVD).

The tool allows a security analyst to enter a CVE ID and view important vulnerability information for research and vulnerability assessment.

## Features

- Accepts a CVE ID from the user
- Validates the CVE format
- Retrieves vulnerability information from the NVD
- Displays the vulnerability description
- Displays CVSS version, score, and severity when available
- Displays affected products and CPE information
- Displays vulnerability references
- Provides the NVD vulnerability page
- Handles connection and lookup errors

## Technologies Used

- Python 3
- NVD CVE API
- Python standard libraries
- JSON
- requests

## Usage

Run the tool with:

```bash
python3 cve_lookup.py
