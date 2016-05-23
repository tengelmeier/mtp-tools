# transform etl_WPDMTP.events.npl into a JSON description
# $ python munge_wpdmtp.py source/etl_WPDMTP.events.npl

import re
import sys
import json
import io
import os.path


def to_int(s):
    s = s.lower()
    if s.startswith('0x'):
        return int(s[2:], 16)
    assert not s.startswith('0')
    return int(s)


# return name, group from an constant named MTP{2}_GROUP_NAME1_NAME2
def split_constant_name(const_name):
    if not const_name.startswith('MTP'):
        return

    command_class, name = const_name.split('_', 1)  # separate MTP / MTP2
    if '_' not in name:
        return

    prefix, suffix = name.split('_', 1)
    return prefix, suffix


def handle_parameter_conditions(value_table, conditions, value):
    if '==' in conditions[0]:
        param_index_desc = conditions[1]
        param_match = re.search('==([A-Z_0-9]+)', param_index_desc)
        index = int(param_match.group(1))

        command_conditions = conditions[0].split('||')
        for command in command_conditions:
            command_match = re.search('==([A-Z_0-9]+)', command)
            command = command_match.group(1)
            param_desc = value_table.get(command, [''] * index)
            param_desc += [''] * (index - len(param_desc))
            param_desc[index - 1] = value = value.strip(' \t"')
            value_table[command] = param_desc


def handle_case_statement(value_table, case_statement):
    case_statement = case_statement.replace('\r\n', '')

    m = re.search('case[ \t]+([^;]+)?:([^;]*)', case_statement)
    if m:
        condition = m.group(1)
        value = m.group(2)

        sub_conditions = condition.split('&&')
        if sub_conditions.__len__() == 2:
            # handle Foo == x && bar == y
            handle_parameter_conditions(value_table, sub_conditions, value)
        else:
            value = value.strip(' \t"')

            condition = condition.replace('(value==', '')
            condition = condition.strip(' \t"()')

            value_table[condition] = value
    else:
        print('Cannot handle: ' + current_case)


def description_tables(table_data):
    lookup = {}
    for key in table_data:
        if 'ToString' in key:
            lookup_key = key.replace('MTP', '').replace('ToString', '')
            lookup_key = lookup_key.lower()

            lookup[lookup_key] = key
    return lookup


def expand_constants(table, constants):
    lookup_table = {}
    for key, value in table.iteritems():
        key_code = constants.get(key)
        if key_code:
            lookup_table[key_code] = value
        else:
            print('Unknown key' + key)
    return lookup_table


def generate_description(data):
    constant_tables = {}
    descriptions = {}
    table_lookup = description_tables(data)

    constants = data['constants']
    for constant_name, value in constants.iteritems():
        prefix, suffix = split_constant_name(constant_name)
        if not prefix:
            continue

        prefix = prefix.lower()
        if not constant_tables.get(prefix):
            constant_tables[prefix] = {}

        constant_tables[prefix][constant_name] = value

    # now build a lookup table 'opcode' => { '0x1234' : { 'name': 'foo', 'code': '0x1234', 'description': 'asfg'}}
    for constants_name, constants_values in constant_tables.iteritems():
        name_table = {}
        if table_lookup.get(constants_name):
            name_table = data[table_lookup[constants_name]]

        constant_descriptions = {}
        for constant_name, constant_value in constants_values.iteritems():
            prefix, suffix = split_constant_name(constant_name)
            constant_desc = name_table.get(constant_name, suffix)
            constant_descriptions[constant_value] = {
                'code': constant_value,
                'name': suffix,
                'description': constant_desc
            }

        description_key = constants_name.capitalize().replace('code', 'Code').replace('prop','Property')
        descriptions[description_key] = constant_descriptions

    parameter_tables = [x for x in data if 'ParamNameLookup' in x]
    for table_name in parameter_tables:
        command_desc = {}
        param_table = data[table_name]
        for constant_name, parameter_list in param_table.iteritems():
            prefix, suffix = split_constant_name(constant_name)
            opcode = constants.get(constant_name, suffix)
            command_desc[opcode] = {
                'code': opcode,
                'name': suffix,
                'parameters': parameter_list
            }
        description_key = table_name.replace('WPD', '').replace('ParamNameLookup', '')
        description_key += 's'
        descriptions[description_key] = command_desc

    return descriptions


# table with content prefix -> (name => val)
parsed_data = {'constants': {}}
current_table = None
current_case = None
accumulated_keys = []
accumulate = False

for l in open(sys.argv[1]):

    # handle constants:
    m = re.match('^const[ \t]+([A-Z0-9_a-z]+)[ \t]+=[ \t]+((0x)?[0-9a-fA-F]+);', l)
    if m:
        name = m.group(1)
        val = m.group(2)

        parsed_data['constants'][name] = val
        continue

    # handle tables - start:
    m = re.match('^Table[ \t]+([A-Z0-9_a-z]+)', l)
    if m:
        current_table_name = m.group(1)
        current_table_name = current_table_name.replace('MTP', '')
        current_table_name = current_table_name.replace('Table', '')

        current_table = {}
        parsed_data[current_table_name] = current_table

        accumulate = False
        continue

    # end
    if l.startswith('}'):
        current_table = None
        continue

    # content
    if current_table is not None:
        if 'case ' in l:
            accumulate = True
            current_case = ''

        if accumulate:
            current_case += l

        if ';' in l:
            handle_case_statement(current_table, current_case)
            accumulate = False

### now all data is collected. Split constants into various tables:

desc = generate_description(parsed_data)
path, fname = os.path.split(sys.argv[1])
filename = os.path.join(path, 'mtp_description.json')
with io.open(filename, 'w', encoding='utf-8') as outfile:
    json = json.dumps(desc, indent=4, sort_keys=True, ensure_ascii=False)
    outfile.write(unicode(json))
