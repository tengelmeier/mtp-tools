from docparsers.ParserBase import ParserBase

import bs4


class TextutilHTMLParagraphParser: # (ParserBase):
    '''
        This class extracts from HTML in the variant

        <p>Name</p>
        <p>Ignored Data With Multiple Tokens</p>
        <p>Key:\t<span> </span>Value</p>

    '''

    def extract_description(self, soup):
        meta_tag = soup.head.find('meta', attrs={'name': 'Generator'})
        if meta_tag and 'Cocoa' in meta_tag['content']:
            commands = self.collect_commands(soup)
            properties = self.collect_properties(soup)

            if len(commands) and len(properties):
                return {ParserBase.COMMANDS_KEY: commands, ParserBase.PROPERTIES_KEY: properties}
            return None  # given a table with Parameter1 -> XXXX, return them in an array


    def collect_text_description(self, tag):
        # find the name - it should be the single-word paragraph before tagname
        name_paragraph = tag.find_previous_sibling(self.is_name_paragraph)
        paragraphs = self.paragraphs_until_empty_line(tag)

        if not name_paragraph or len(paragraphs) < 2:
            return None

        description = {u'name': name_paragraph.string}
        for p in paragraphs:
            c1, c2 = self.extract_first_paragraph_columns(p)
            if c1 and c2:
                description[c1] = c2
        return description

    def collect_commands(self, soup):
        descriptions = []
        opcode_p = soup.find_all(string=self.starts_with_opcode)
        for p in opcode_p:
            tag = p.parent
            desc = self.collect_text_description(tag)
            if desc and len(desc.keys()) >= 4:
                descriptions.append(desc)
        return descriptions

    def collect_properties(self, soup):
        descriptions = []
        for p_text in soup.find_all(string=self.starts_with_propertycode):
            tag = p_text.parent
            desc = self.collect_text_description(tag)
            if desc:
                descriptions.append(desc)
        return descriptions


class TextutilHTMLTableParser(ParserBase):
    # public interface
    def extract_description(self, soup):
        meta_tag = soup.head.find('meta', attrs={'name': 'Generator'})
        if meta_tag and 'Cocoa' in meta_tag['content']:
            commands = self.collect_commands(soup)
            properties = self.collect_properties(soup)

            if len(commands) and len(properties):
                return {ParserBase.COMMANDS_KEY: commands, ParserBase.PROPERTIES_KEY: properties}
            return None  # given a table with Parameter1 -> XXXX, return them in an array


    def extract_parameters(self, table):
        parameters = []
        for row in table.tr.find_next_siblings('tr'):  # start from the row after headers
            c1, c2 = self.extract_first_columns(row)
            if c1 and 'Parameter' in c1 and c2 and c2 != 'None':
                parameters.append(c2)
        return parameters


    # collect CommandDescription -> Parameter Table -> ResponseParameter Table -> ResponseCode Table
    def extract_command_description_table(self, table):
        """
        Extract a the description of an command
            The command description is not in a table,
            so a text block needs to be parsed
            The assumption is that this text block starts after a few blank lines after another table.
            This might be problematic for the first command, but this should be getDeviceInfo anyway
        """
        name_paragraph = table.find_previous_sibling(self.is_name_paragraph)
        if not name_paragraph:
            return None, None

        name = name_paragraph.string

        command_description = self.extract_table(table)
        command_description['Command Name'] = name

        for table in table.find_next_siblings('table'):
            row_name, row_value = self.extract_first_columns(table.tr)

             # now add the subsequent tables: 'Operation Parameter', 'Response Parameter', 'Response Code'
            if row_name:
                row_name = self.normalize_row_name(row_name)
                if 'OperationParameter' in row_name:
                    command_description['parameters'] = self.extract_parameters(table)
                elif 'ResponseParameter' in row_name:
                    command_description['response'] = self.extract_parameters(table)
                elif 'ResponseCode' in row_name:
                    command_description['response_codes'] = self.extract_table(table,skipFirstRow=True)
                else:
                    return name, command_description
            else:
                if table:
                    print('Illegal table:' + table.prettify() )
                # return name, command_description
        # We should never get here..
        return None, None


    def collect_commands(self, soup):
        command_descriptions = []
        for table in soup.find_all('table'):
            row_name, row_value = self.extract_first_columns(table.tr)
            row_name = self.normalize_row_name(row_name)

            if row_name:
                if 'OperationCode' in row_name:
                    name, command_description = self.extract_command_description_table(table)
                    if name and len(command_description) and len(command_description) < 20:
                        command_description[u'name'] = name
                        command_descriptions.append(command_description)
        return command_descriptions


    def collect_properties(self, soup):
        property_descriptions = []
        property_description = {}
        for table in soup.find_all('table'):
            row_name, row_value = self.extract_first_columns(table.tr)
            if row_name:
                row_text = row_name  # row_name.text
                if 'Property' in row_name and 'Code' in row_name:
                    if len(property_description) > 4 and len(property_description) < 30:
                        property_descriptions.append(property_description)

                    if True:
                        name_paragraph = table.find_previous_sibling(self.is_name_paragraph)
                        if name_paragraph:
                            name = name_paragraph.string

                            property_description = self.extract_table(table)
                            property_description[u'name'] = name
                    else:
                        # the code does not work with nested tables (See Property D026 of a D5300)
                        property_description = {}

                elif 'PropertyValue' in row_name:
                    property_description[u'Values'] = self.extract_table(table, skipFirstRow=True)

        # add the last desc:
        if property_description.get('PropertyCode'):
            property_descriptions.append(property_description)

        return property_descriptions
