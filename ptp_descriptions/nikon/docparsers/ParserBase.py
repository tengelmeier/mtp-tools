'''
    Baseclass for various documentation parsers
    A collection of shared utility functions (predicates etc.)


'''


class ParserBase(object):
    (OPERATION_CODE_KEY, OPERATION_PARAMETER_KEY) = ('OperationCode', 'OperationParameter')
    (RESPONSE_CODE_KEY, RESPONSE_PARAMETER_KEY) = ('ResponseCode', 'ResponseParameter')
    (PROPERTY_CODE_KEY) = ('PropertyCode')
    (COMMANDS_KEY, PROPERTIES_KEY) = ('operations','properties')

    def __init__(self):
        self.name_lookup = {
            'Property Code': ParserBase.PROPERTY_CODE_KEY,
            'Response Code': ParserBase.RESPONSE_CODE_KEY,
            'Operation Code': ParserBase.OPERATION_CODE_KEY,
            'Operation Parameter': ParserBase.OPERATION_PARAMETER_KEY,
            'Response Parameter': ParserBase.RESPONSE_PARAMETER_KEY
        }


    def normalize_row_name(self, name):
        return self.name_lookup.get(name, name)

    ################# Table

    # given a row in html, return the text in the first two rows
    def extract_first_columns(self, row):
        col1_text = row.td.p.string
        col2 = row.td.find_next_sibling('td')
        if col2:
            col2_text = col2.p.string
            return col1_text, col2_text
        return col1_text, None

     # iterate over all rows and extract them into key <-> value pairs
    def extract_table(self, table, skipFirstRow=False):
        values = {}
        if skipFirstRow:
            rows = table.tr.find_next_siblings('tr')  # start from the row after headers
        else:
            rows = table.find_all('tr')

        for row in rows:
            c1, c2 = self.extract_first_columns(row)
            if c1 and c2 and c2 != 'None':
                values[c1] = c2
        return values

    ################### Text

    # given an <p> tag, return the text in the <p> and after the first <span>
    def extract_first_paragraph_columns(self, paragraph):
        texts = paragraph.text.split(':')  # [x for x in paragraph.stripped_strings if len(x) > 2]
        texts = [x.strip() for x in texts]
        c1 = None
        c2 = None
        if len(texts) > 0:
            c1 = texts[0]
        if len(texts) > 1:
            c2 = texts[1]
        return c1, c2


    # starting from an tag, get everything until the next following table tag
    def paragraphs_until_table(self, tag):
        paragraphs = []
        while tag:
            tag = tag.next_sibling
            if tag and tag.name == 'p':
                paragraphs.append(tag)
            elif tag and tag == 'table':
                return paragraphs
        return paragraphs


    def paragraphs_until_empty_line(self, tag):
        paragraphs = []
        while tag:
            if tag and tag.name == 'p':
                if not self.is_filled_paragraph(tag):
                    return paragraphs
                paragraphs.append(tag)
            tag = tag.next_sibling
        return paragraphs


    #################### Predicates

    def starts_with_opcode(self, s):
        return s and (s.startswith('OperationCode') or s.startswith('Operation Code'))

    def starts_with_propertycode(self, s):
        match = s and (s.startswith('PropertyCode') or s.startswith('Property Code'))
        # print( u'{string} => {match}'.format(string=s, match=match) )
        return match

    # predicate to match if the paragraph is empty
    def is_filled_paragraph(self, tag):
        return tag.name == 'p' and tag.text and len(tag.text) > 0

    # predicate to match if the paragraph is followed by an table tag
    def is_last_paragraph(self, tag):
        while True:
            tag = tag.next_element()
            if 'table' in tag.name:
                return True
            elif 'p' in tag.name:
                return False

    def is_name_paragraph(self, x):
        if self.is_filled_paragraph(x) and x.string is not 'Standard':
            words = x.text.split()
            return len(words) == 1
        return False
