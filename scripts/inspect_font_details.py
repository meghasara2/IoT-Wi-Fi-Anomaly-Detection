import docx
import xml.etree.ElementTree as ET

doc = docx.Document('Project_Report_CCNS.docx')
root = ET.fromstring(doc.styles.element.xml)
ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
for s in root.findall('w:style', ns):
    name = s.find('w:name', ns)
    rPr = s.find('w:rPr', ns)
    rFonts = rPr.find('w:rFonts', ns) if rPr is not None else None
    sz = rPr.find('w:sz', ns) if rPr is not None else None
    font_name = rFonts.attrib if rFonts is not None else None
    size = sz.attrib if sz is not None else None
    if name is not None:
        style_name = name.attrib.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val')
        if style_name in ['Normal', 'Body Text 2', 'Heading 1', 'Heading 2', 'Heading 3', 'Front Heading', 'Abstract Text', 'Reference Text']:
            print(f"{style_name}: font={font_name}, sz={size}")
