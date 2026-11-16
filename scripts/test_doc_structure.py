import docx
import shutil

# Make a test copy
shutil.copyfile('Project_Report_CCNS.docx', 'scratch/test_copy.docx')
doc = docx.Document('scratch/test_copy.docx')

print(f"Original paragraphs: {len(doc.paragraphs)}, Original tables: {len(doc.tables)}")

# Check Section 0 vs Section 1 paragraphs
p_sect_break = None
for i, p in enumerate(doc.paragraphs):
    if p._p.xpath('./w:pPr/w:sectPr'):
        p_sect_break = i
        break

print(f"Section break found at paragraph {p_sect_break}")
print(f"Paragraphs before section break: {p_sect_break + 1}")
print(f"Paragraphs after section break: {len(doc.paragraphs) - (p_sect_break + 1)}")
