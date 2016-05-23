#!/usr/bin/env python

"""
build_mtp_dissector.py: Generate an Lua wireshark dissector for PTP / MTP

Constants and Parameters are extracted with additional scripts to intermediate JSON files
and then combined with a Jinja template.

Usage: build_mtp_dissector.py -p ptp_lgpl_license -t code_templates/wireshark/dissector.lua -d ../wireshark/x_mtp_dissector.lua

with {source} pointing to an folder


"""

__author__      = "Thomas Engelmeier"

import os
import io
import sys
import json
import argparse

from jinja2 import Environment, FileSystemLoader

parser = argparse.ArgumentParser('Create an wireshark dissector based on PTP data and a template')
parser.add_argument('-p','--ptp_description_folder')
parser.add_argument('-t','--template_file')
parser.add_argument('-d','--destination_file')
args = parser.parse_args()

template_folder, template_name =  os.path.split(args.template_file)
template_env = Environment(loader=FileSystemLoader(template_folder))
template_env.lstrip_blocks = True
template_env.trim_blocks = True

json_path = os.path.join(args.ptp_description_folder, 'mtp_description.json')
with open(json_path, 'r') as fp:
    description = json.load(fp)

# vendor support: Transform individual vendor json files
description['extensions'] = {}

vendor_definitions = [name for name in os.listdir(args.ptp_description_folder) if 'ptp_' in name and '.json' in name]
for vendor_definition in vendor_definitions:
    json_path = os.path.join(args.ptp_description_folder, vendor_definition)
    with open(json_path, 'r') as fp:
        vendor_description = json.load(fp)
        vendor = vendor_definition.replace('ptp_', '').replace('.json','')
        description['extensions'][vendor] = vendor_description

template = template_env.get_template(template_name)
text = template.render(tables = description)

with io.open(args.destination_file,'w', encoding='utf8') as fp:
    fp.write(text)

