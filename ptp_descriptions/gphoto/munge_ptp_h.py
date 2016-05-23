# transform ptp.h into in JSON based descriptions
# $ python munge_ptp_h.py ptp2/ptp.h
#

import re
import sys

import os
import io
import json

def create_vendor_descriptions(data, vendors):
    descriptions = {}

    explaination = {
        'DPC': 'DevicePropertyCode',
        'EC': 'EventCode',
        'OC': 'OpCode',
        'OFC': 'FormatCode',
        'OPC': 'ObjectPropertyCode',
        'RC': 'ResponseCode',
    }

    for key in vendors:
        descriptions[key.upper()] = {}

    for table_name in explaination.keys():
        table = data[table_name]
        for property_name, property_code in table.iteritems():
            if '_' in property_name:
                vendor, property_name_mainder = property_name.split('_', 1)
                if property != None and vendor in vendors:
                    vendor_desc = descriptions[vendor.upper()]
                    expanded_table_name = explaination[table_name]
                    if not vendor_desc.get(expanded_table_name):
                        vendor_desc[expanded_table_name] = {}
                    vendor_desc[expanded_table_name][property_code] = property_name_mainder

    return descriptions


# prefix -> (name => val)
data = {}

for l in open(sys.argv[1]):
    m = re.match('^#define[ \t]+([A-Z0-9_a-z]+)[ \t]+((0x)?[0-9a-fA-F]+)$', l)
    if not m:
        continue

    name = m.group(1)
    val = m.group(2)

    if not name.startswith('PTP_'):
        continue

    name = name[4:]
    if '_' not in name :
        continue
        
    prefix, suffix = name.split('_', 1)
    if prefix not in data:
        data[prefix] = {}

    data[prefix][suffix] = val

vendors = set(data['VENDOR'].keys())
# sys.stderr.write('vendors %s' % vendors)

# brilliant..  EK=EASTMAN_KODAK
# use a hardoced list. Vendor names don't match the IDs used in constants (which are also not consistent)
vendors = set( ['ANDROID','CANON','CASIO','EK','FUJI','LEICA','MTP','NIKON','OLYMPUS','RICOH','SONY','Sony'])

descriptions = create_vendor_descriptions(data,vendors)
path, fname = os.path.split(sys.argv[1])

for vendor in vendors:
    filename = os.path.join(path, 'ptp_{vendor}.json'.format(vendor=vendor.lower()))
    if descriptions.get(vendor):
        with io.open(filename, 'w', encoding='utf-8') as outfile:
            json_data = json.dumps(descriptions[vendor], indent=4, sort_keys=True, ensure_ascii=False)
            outfile.write(unicode(json_data))
