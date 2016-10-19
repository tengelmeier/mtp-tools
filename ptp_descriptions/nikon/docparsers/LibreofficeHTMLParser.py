'''
    Libreoffice exports the word document data as

    <h4>5.5.2.15.WbTuneFluorescentType</h4>
<ul>
	<li/><p>PropertyCode	:  0xDXXXX</p>
	<li/><p>DataType		:  UINT8</p>
	<li/><p>Description form	:  Range</p>
	<li/><p>Get/Set		:  Get/Set</p>
	<li/><p>DefaultValue	:  3</p>
</ul>
<p><br/>


<h3>5.2.1.GetDeviceInfo</h3>
<p>The operation by this OperationCode ,,,, </p>
<p><br/>
</p>
<ul>
<li/><p>OperationCode: 		0x1001</p>
<li/><p>Parameter1:			None</p>
<li/><p>Parameter2:			None</p>
<li/><p>Parameter3:			None</p>
<li/><p>Data:			DeviceInfo data set</p>
<li/><p>Data direction:		From camera to host</p>
<li/><p>ResponseCode:		OK,Parameter_Not_Supported, Incomplete_Transfer</p>
<li/><p>Response Parameter:		None</p>
</ul>
<dl>
	<dd>
	<table>
		<tr><td><p>ResponseCode</p></td>  <td><p>Description</font></p></td></tr>
....



'''


from docparsers.ParserBase import ParserBase


class LibreofficeHTMLParser(ParserBase):
    # public interface

    def is_header(self, tag):
        return tag.name.startswith('h')

    def extract_description(self, soup):
        meta_tag = soup.head.find('meta', attrs={'name':'generator'})
        if meta_tag and 'LibreOffice' in meta_tag['content']:
            commands = self.extract_commands(soup.body)
            properties = self.extract_properties(soup.body)

            if len(commands) and len(properties):
                return {ParserBase.COMMANDS_KEY:commands, ParserBase.PROPERTIES_KEY:properties}
        return None  # given a table with Parameter1 -> XXXX, return them in an array


    def extract_items(self, container):
        d = {}
        paragraphs = container.find_all('p')
        for p in paragraphs:
            key, value = self.extract_first_paragraph_columns(p)
            if key and value:
                d[key] = value
        return d

    def extract_commands(self, soup):
        descriptions = []
        for tag in soup.find_all('p', string=self.starts_with_opcode):
            container = tag.find_parent('ul')
            if not container:
                continue
            name_paragraph = container.find_previous_sibling(self.is_header)
            if name_paragraph:
                name = name_paragraph.text
                d = self.extract_items(container)
                d[u'name'] = name.strip()
                descriptions.append(d)
        return descriptions


    def extract_properties(self, soup):
        descriptions = []
        tags = soup.find_all('p', string=self.starts_with_propertycode)
        for tag in tags:
            container = tag.find_parent('ul')
            if not container:
                continue
            name_paragraph = container.find_previous_sibling(self.is_header)
            if name_paragraph:
                name = name_paragraph.text
                d = self.extract_items(container)
                d[u'name'] = name.strip()
                descriptions.append(d)
        return descriptions