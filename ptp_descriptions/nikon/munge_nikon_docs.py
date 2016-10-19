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

__author__      = "Thomas Engelmeier"

# prefix -> (name => val)
data = {}

name_lookup = {
    'Property Code' : 'PropertyCode',
    'Response Code' : 'ResponseCode',
    'Operation Code': 'OperationCode',
    'Operation Parameter': 'OperationParameter',
    'Response Parameter': 'ResponseParameter'

}

def normalize_row_name(name):
    return name_lookup.get(name, name)


# given a row in html, return the text in the first two rows
def extract_first_columns(row):
    col1_text = row.td.p.string
    col2 = row.td.find_next_sibling('td')
    if col2:
        col2_text = col2.p.string
        return col1_text, col2_text
    return col1_text, None


# given an <p> tag, return the text in the <p> and after the first <span>
def extract_first_paragraph_columns(paragraph):
    texts = paragraph.text.split(':') # [x for x in paragraph.stripped_strings if len(x) > 2]
    texts = [x.strip() for x in texts]
    c1 = None
    c2 = None
    if  len(texts) > 0:
        c1 = texts[0]
    if  len(texts) > 1:
        c2 = texts[1]
    return c1, c2


# iterate over all rows and extract them into key <-> value pairs
def extract_table(table, skipFirstRow=False):
    values = {}
    if skipFirstRow:
        rows = table.tr.find_next_siblings('tr') # start from the row after headers
    else:
        rows = table.find_all('tr')

    for row in rows:
        c1, c2 = extract_first_columns(row)
        if c1 and c2 and c2 != 'None':
            values[c1] = c2
    return values


# starting from an tag, get everything until the next following table tag
def paragraphs_until_table(tag):
    paragraphs = []
    while tag:
        tag = tag.next_sibling
        if tag and tag.name == 'p':
            paragraphs.append(tag)
        elif tag and tag == 'table':
            return paragraphs
    return paragraphs


# predicate to match if the paragraph is empty
def is_filled_paragraph(tag):
    return tag.name == 'p' and tag.text and len( tag.text ) > 0


def paragraphs_until_empty_line(tag):
    paragraphs = []
    while tag:
        if tag and tag.name == 'p':
            if not is_filled_paragraph(tag):
                return paragraphs
            paragraphs.append(tag)
        tag = tag.next_sibling
    return paragraphs


# predicate to match if the paragraph is followed by an table tag
def is_last_paragraph(tag):
    while True:
        tag = tag.next_element()
        if 'table' in tag.name:
            return True
        elif 'p' in tag.name:
            return False


# given an table tag, extract the command description from there
def extract_command_description(table):
    """
    Extract a the description of an command
        The command description is not in a table,
        so a text block needs to be parsed
        The assumption is that this text block starts after a few blank lines after another table.
        This might be problematic for the first command, but this should be getDeviceInfo anyway

    """

    command_description = {}
    previous_table = table.find_previous_sibling('table')
    current_tag = previous_table.find_next_siblings('p')
    while len(current_tag.string) == 0:
        current_tag = current_tag.next()

    command_description[u'name'] = current_tag.string
    current_tag = current_tag.next()
    while not is_last_paragraph(current_tag):
        col1, col2 = extract_first_paragraph_columns(current_tag)
        if col1 and col2:
            command_description['col1'] = col2


# given a table with Parameter1 -> XXXX, return them in an array
def extract_parameters(table):
    parameters = []
    for row in table.tr.find_next_siblings('tr'): # start from the row after headers
        c1, c2 = extract_first_columns(row)
        if c1 and 'Parameter' in c1 and c2 and c2 != 'None':
            parameters.append(c2)
    return parameters


def extract_description_text(paragraph):
    description = {}
    previous_table = paragraph.find_previous_sibling('table')

    # find the name - it should be the first paragraph after a table
    name_paragraph = next((x for x in previous_table.next_siblings if is_filled_paragraph(x) and x.string is not 'Standard'), None)
    paragraphs = paragraphs_until_table(name_paragraph)
    for p in paragraphs:
        c1, c2 = extract_first_paragraph_columns(p)
        if c1 and c2:
            description[c1] = c2

    return description


def extract_command_description_text(paragraph):
    description = extract_description_text(paragraph)
    value_tag = paragraph.find_next_sibling('table')
    # check and extract the responses

    return description


def extract_property_description_text(paragraph):
    description = collect_text_description(paragraph) # extract_description_text(paragraph)
    # value_tag = paragraph.find_next_sibling('table')

    return description


# collect CommandDescription -> Parameter Table -> ResponseParameter Table -> ResponseCode Table
def extract_command_description_table(table):
    """
    Extract a the description of an command
        The command description is not in a table,
        so a text block needs to be parsed
        The assumption is that this text block starts after a few blank lines after another table.
        This might be problematic for the first command, but this should be getDeviceInfo anyway

    """

    # previous_table = table.find_previous_sibling('table')

    # find the name - it should be the first paragraph after a table
    # name_paragraph = next((x for x in previous_table.next_siblings if is_filled_paragraph(x) and x.string is not 'Standard'), None)

    name_paragraph = table.find_previous_sibling(is_name_paragraph)
    if not name_paragraph:
        return None, None

    name = name_paragraph.string

    command_description = extract_table(table)
    command_description['Command Name'] = name

    for table in table.find_next_siblings('table'):
        row_name, row_value = extract_first_columns(table.tr)

         # now add the subsequent tables: 'Operation Parameter', 'Response Parameter', 'Response Code'
        if row_name:
            row_name = normalize_row_name(row_name)
            if 'OperationParameter' in row_name:
                command_description['parameters'] = extract_parameters(table)
            elif 'ResponseParameter' in row_name:
                command_description['response'] = extract_parameters(table)
            elif 'ResponseCode' in row_name:
                command_description['response_codes'] = extract_table(table,skipFirstRow=True)
            else:
                return name, command_description
        else:
            if table:
                print('Illegal table:' + table.prettify() )
            # return name, command_description
    # We should never get here..
    return None, None



def is_name_paragraph(x):
    if is_filled_paragraph(x) and x.string is not 'Standard':
        words = x.text.split()
        return len(words) == 1
    return False


def collect_text_description(tag):
    # find the name - it should be the single-word paragraph before tagname
    name_paragraph = tag.find_previous_sibling(is_name_paragraph)
    paragraphs = paragraphs_until_empty_line(tag)

    if not name_paragraph or len(paragraphs) < 2:
        return None

    description = {u'name': name_paragraph.string}
    for p in paragraphs:
        c1, c2 = extract_first_paragraph_columns(p)
        if c1 and c2:
            description[c1] = c2

    return description

def starts_with_opcode(s):
    return s.startswith('OperationCode') or s.startswith('Operation Code')

def starts_with_propertycode(s):
    return s.startswith('PropertyCode') or s.startswith('Property Code')


# Collect commands
def collect_commands_from_text(soup):
    descriptions = []
    opcode_p = soup.find_all(string=starts_with_opcode)
    for p in opcode_p:
        tag = p.parent
        desc = collect_text_description(tag)
        if desc and len(desc.keys()) >= 4:
            descriptions.append(desc)
    return descriptions


def collect_commands_from_tables(soup):
    command_descriptions = []
    for table in soup.find_all('table'):
        row_name, row_value = extract_first_columns(table.tr)
        row_name = normalize_row_name(row_name)

        if row_name:
            if 'OperationCode' in row_name:
                name, command_description = extract_command_description_table(table)
                if name and len(command_description) and len(command_description) < 20:
                    command_description[u'name'] = name
                    command_descriptions.append(command_description)

                    # command_descriptions[name] = command_description

    return command_descriptions

def collect_properties_from_table(soup):
    property_descriptions = []
    property_description = {}
    for table in soup.find_all('table'):
        row_name, row_value = extract_first_columns(table.tr)
        if row_name:
            row_text = row_name  # row_name.text
            if 'Property' in row_name and 'Code' in row_name:
                if len( property_description ) > 4 and len( property_description ) < 30:
                    property_descriptions.append(property_description)

                if True:
                    name_paragraph = table.find_previous_sibling(is_name_paragraph)
                    if name_paragraph:
                        name = name_paragraph.string

                        property_description = extract_table(table)
                        property_description[u'name'] = name
                else:
                    # the code does not work with nested tables (See Property D026 of a D5300)
                    property_description = {}

            elif 'PropertyValue' in row_name:
                property_description[u'Values'] = extract_table(table,skipFirstRow=True)


    # add the last desc:
    if property_description.get('PropertyCode'):
        property_descriptions.append(property_description)
        # property_descriptions[property_description['PropertyCode']] = property_description

    return property_descriptions


def collect_commands(soup):
    command_descriptions = collect_commands_from_text(soup)
    if len(command_descriptions) < 10:
        print(' * No operations - falling back to scan tables')
        command_descriptions = collect_commands_from_tables(soup)

    return command_descriptions


# collect PropertyDescription -> PropertyValuesTable
def collect_properties(soup):
    property_descriptions = collect_properties_from_paragraph(soup)
    if len(property_descriptions) < 10:
        print(' * No properties - falling back to scan tables')
        property_descriptions = collect_properties_from_table(soup)
    return property_descriptions


# tag 'PropertyCode' <-> descriptions
def collect_properties_from_paragraph(soup):
    descriptions = []
    for p_text in soup.find_all(string=starts_with_propertycode):
        tag = p_text.parent
        desc = collect_text_description(tag)
        if desc:
            descriptions.append(desc)
    return descriptions


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

def transform_file(path, parse_verbose):
    soup = BeautifulSoup(open(path), 'html.parser')

    camera_description = {}
    camera_description['operations'] = collect_commands(soup)
    camera_description['properties'] = collect_properties(soup)

    if parse_verbose:
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

# sdk_descriptions = [name for name in os.listdir(doc_base_path)] # if 'UsbMtpE' in name and '.html' in name]
for root, dirs, files in os.walk(doc_base_path):
    # print root, "consumes",
    for name in [name for name in files if ('UsbMtpE' in name or 'UsbPtpE' in name) and '.html' in name]:
        path = join(root, name)
        print ('Transforming ' + name)
        description = transform_file(path, parse_verbose)

        dest_path = join(root, name.replace('.html','.json'))
        with io.open(dest_path, 'w', encoding='utf-8') as outfile:
            json_data = json.dumps(description, indent=4, sort_keys=True, ensure_ascii=False)
            outfile.write(unicode(json_data))
