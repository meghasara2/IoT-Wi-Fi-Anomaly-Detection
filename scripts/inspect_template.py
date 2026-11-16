import docx

doc = docx.Document('Project_Report_CCNS.docx')
print(f'Total sections: {len(doc.sections)}')
for i, s in enumerate(doc.sections):
    print(f'Section {i}: top={s.top_margin.inches}in, bottom={s.bottom_margin.inches}in, left={s.left_margin.inches}in, right={s.right_margin.inches}in')
    print(f'  page_width={s.page_width.inches}in, page_height={s.page_height.inches}in')
    for p in s.header.paragraphs:
        if p.text.strip(): print('    Header:', p.text)
    for p in s.footer.paragraphs:
        if p.text.strip(): print('    Footer:', p.text)

print(f'\nTotal tables: {len(doc.tables)}')
for i, t in enumerate(doc.tables):
    print(f'Table {i}: {len(t.rows)} rows, {len(t.columns)} cols')
    for r in t.rows[:2]:
        print('  Row:', [c.text.strip().replace('\n', ' ') for c in r.cells[:4]])
