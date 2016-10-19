#!/usr/bin/env python

"""
munge_nikon_docs.py: Extract constants and property values from Nikon camera SDK docs


Usage: munge_nikon_docs.py -p ptp_lgpl_license -t code_templates/wireshark/dissector.lua -d ../wireshark/x_mtp_dissector.lua

with {source} pointing to an folder


"""

from bs4 import BeautifulSoup
import re

import os
from os.path import join
import argparse
import io
import json
from sets import Set
from docparsers.TextutilHTMLParser import TextutilHTMLParagraphParser, TextutilHTMLTableParser
from docparsers.LibreofficeHTMLParser import LibreofficeHTMLParser

__author__      = "Thomas Engelmeier"

# prefix -> (name => val)
data = {}

def print_stats(name, items):
    min_props = 999999
    max_props = 0
    all_keys = Set()

    if not items or len(items) == 0:
        print('    !!!! No {name} extracted'.format(name=name))
        return

    for item in items:
        keys = item.keys()
        min_props = min(min_props, len(keys))
        max_props = max(max_props, len(keys))
        all_keys.update(keys)

        if len(keys) < 4:
            print keys

    print('   {name} has {count} elements with {min}...{max} keys'.format(name=name, count=len(items), min=min_props, max=max_props))
    print('   Keys:' + ','.join(all_keys))
    print('')

# Handle one file:

def transform_file(path, parsers, parse_verbose):
    soup = BeautifulSoup(open(path), 'html.parser')

    for parser in parsers:
        print(' Trying {parser}'.format(parser=parser.__class__.__name__))
        camera_description = parser.extract_description(soup)
        if camera_description:
            break
        else:
            print( ' Parser {parser} failed'.format(parser = parser.__class__.__name__) )

    if parse_verbose:
        if not camera_description:
            print(' *** Not Parseable')
        else:
            print_stats('operations', camera_description['operations'])
            print_stats('properties', camera_description['properties'])

    return camera_description


# expectation is to find a bunch of folders with the following structure
# {Camera Model SDK}/
#         Command
#              English <== .doc files here converted to .html (*)
#              Japanese
#         Module
# Use 'textutil -convert html' to transform the description docs
# A handful of descriptions don't work becaus TextUtil can not cope with newer word docs
# Here an html export from libreoffice works

parser = argparse.ArgumentParser('Generate descriptions from Nikon camera description .html extracted from the SDK docs')
parser.add_argument('-n','--nikon_description_folder')
parser.add_argument('-v','--verbose', action='store_true')
args = parser.parse_args()

parse_verbose = False
if args.verbose:
    parse_verbose = True

doc_base_path = args.nikon_description_folder

# vendor support: Transform individual vendor json files
# description['extensions'] = {}

# parsers = [TextutilHTMLParagraphParser(), TextutilHTMLTableParser(), LibreofficeHTMLParser()]
parsers = [LibreofficeHTMLParser()]

# sdk_descriptions = [name for name in os.listdir(doc_base_path)] # if 'UsbMtpE' in name and '.html' in name]
for root, dirs, files in os.walk(doc_base_path):
    # print root, "consumes",
    for name in [name for name in files if ('UsbMtpE' in name or 'UsbPtpE' in name) and '.html' in name]:
        path = join(root, name)
        print ('Transforming ' + name)
        description = transform_file(path, parsers, parse_verbose)

        dest_path = join(root, name.replace('.html','.json'))
        with io.open(dest_path, 'w', encoding='utf-8') as outfile:
            json_data = json.dumps(description, indent=4, sort_keys=True, ensure_ascii=False)
            outfile.write(unicode(json_data))
