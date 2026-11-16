import docx
import shutil

shutil.copyfile('Project_Report_CCNS.docx', 'scratch/test_clean.docx')
doc = docx.Document('scratch/test_clean.docx')

# Remove tables 3 to 7 (reverse order)
for t in doc.tables[3:][::-1]:
    t._element.getparent().remove(t._element)

# Remove paragraphs after paragraph 12 (reverse order)
for p in doc.paragraphs[13:][::-1]:
    p._element.getparent().remove(p._element)

print("Remaining paragraphs:", len(doc.paragraphs))
print("Remaining tables:", len(doc.tables))
print("Sections:", len(doc.sections))

doc.save('scratch/test_clean_saved.docx')
print("Saved cleanly!")
