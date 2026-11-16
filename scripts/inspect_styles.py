import docx

doc = docx.Document('Project_Report_CCNS.docx')

for style_name in ['Front Heading', 'Front Heading Plain', 'Heading 1', 'Heading 2', 'Heading 3', 'Body Text 2', 'Abstract Text', 'Equation Line', 'Reference Text', 'Normal']:
    try:
        s = doc.styles[style_name]
        font = s.font
        print(f"Style: '{style_name}'")
        print(f"  font: {font.name}, size: {font.size.pt if font.size else 'None'} pt, bold: {font.bold}, italic: {font.italic}")
    except Exception as e:
        print(f"Style '{style_name}': {e}")

print("\n--- Inspecting first row of Table 0 (TOC) ---")
t0 = doc.tables[0]
for r in t0.rows[:10]:
    cells = [c.text.strip().replace('\n', ' ') for c in r.cells]
    print(" ", cells)
