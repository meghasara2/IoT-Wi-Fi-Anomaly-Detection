import docx
import xml.etree.ElementTree as ET

doc = docx.Document('Project_Report_CCNS.docx')
root = ET.fromstring(doc.styles.element.xml)
ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
doc_def = root.find('w:docDefaults', ns)
if doc_def is not None:
    print(ET.tostring(doc_def, encoding='unicode'))
