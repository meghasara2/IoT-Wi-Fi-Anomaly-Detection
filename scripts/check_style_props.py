import docx

doc = docx.Document('Project_Report_CCNS.docx')

styles_to_check = ['Front Heading', 'Front Heading Plain', 'Heading 1', 'Heading 2', 'Heading 3', 'Body Text 2', 'Abstract Text', 'Equation Line', 'Reference Text', 'Normal', 'ListText']

for s_name in styles_to_check:
    if s_name in doc.styles:
        s = doc.styles[s_name]
        p_pr = s._element.pPr
        jc_val = "None"
        sp_info = "None"
        if p_pr is not None:
            jc = p_pr.find('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}jc')
            if jc is not None:
                jc_val = jc.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}val')
            spacing = p_pr.find('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}spacing')
            if spacing is not None:
                sp_info = f"before={spacing.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}before')}, after={spacing.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}after')}, line={spacing.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}line')}"
        print(f"Style '{s_name}': jc={jc_val}, spacing: {sp_info}")
