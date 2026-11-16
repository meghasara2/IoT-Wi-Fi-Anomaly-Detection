from pptx import Presentation
prs = Presentation('Review1_Presentation.pptx')
slide = prs.slides[1]

for shape in slide.shapes:
    if shape.has_text_frame:
        print(f"TextBox: {shape.name}")
        for p in shape.text_frame.paragraphs:
            for r in p.runs:
                color = "Default"
                if r.font.color and r.font.color.type == 1:
                    color = r.font.color.rgb
                elif r.font.color and r.font.color.type == 2:
                    color = r.font.color.theme_color
                print(f"  Color: {color}")
                break
            break
    if shape.name in ["Rectangle 1", "Rectangle 2"]:
        fill = shape.fill
        if fill.type == 1:
            print(f"{shape.name} fill color: {fill.fore_color.rgb}")
        else:
            print(f"{shape.name} fill color type: {fill.type}")
