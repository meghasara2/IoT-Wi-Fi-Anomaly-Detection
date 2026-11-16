from pptx import Presentation
from pptx.util import Emu, Pt, Inches
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
import datetime

prs = Presentation()
prs.slide_width = Emu(10160000)
prs.slide_height = Emu(7620000)

# Colors
TOP_BAR_COLOR = RGBColor(0x2E, 0x75, 0xB6)
BOTTOM_BAR_COLOR = RGBColor(0x0B, 0x30, 0x5E)
TITLE_COLOR = RGBColor(0x0B, 0x30, 0x5E)
TEXT_COLOR = RGBColor(0, 0, 0)

def add_common_elements(slide, slide_num):
    top_bar = slide.shapes.add_shape(1, 0, 0, Emu(10160000), Emu(54864))
    top_bar.fill.solid()
    top_bar.fill.fore_color.rgb = TOP_BAR_COLOR
    top_bar.line.fill.background()
    
    bottom_bar = slide.shapes.add_shape(1, 0, Emu(7388352), Emu(10160000), Emu(228600))
    bottom_bar.fill.solid()
    bottom_bar.fill.fore_color.rgb = BOTTOM_BAR_COLOR
    bottom_bar.line.fill.background()
    
    try:
        slide.shapes.add_picture("Picture1.png", Emu(7863840), Emu(-45720), Emu(2194560), Emu(1252728))
    except Exception as e:
        print("Logo not found", e)
        
    txBox = slide.shapes.add_textbox(Emu(9235440), Emu(7269480), Emu(731520), Emu(228600))
    tf = txBox.text_frame
    tf.word_wrap = False
    p = tf.paragraphs[0]
    p.text = f"{slide_num}/13"
    p.font.size = Pt(12)
    p.font.name = 'Arial'
    p.font.color.rgb = RGBColor(255, 255, 255)

def add_title_slide():
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    add_common_elements(slide, 1)
    
    # Title
    txBox = slide.shapes.add_textbox(Emu(274320), Emu(1957816), Emu(9144000), Emu(1015663))
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "AI-Assisted IoT Wi-Fi Anomaly Detection"
    p.font.size = Pt(36)
    p.font.bold = True
    p.font.name = 'Times New Roman'
    p.font.color.rgb = TITLE_COLOR
    p.alignment = PP_ALIGN.CENTER
    
    # Project Review-2
    txBox2 = slide.shapes.add_textbox(Emu(3815394), Emu(1308968), Emu(2500000), Emu(400110))
    p2 = txBox2.text_frame.paragraphs[0]
    p2.text = "Project Review-2"
    p2.font.size = Pt(22)
    p2.font.bold = True
    p2.font.name = 'Times New Roman'
    p2.font.color.rgb = RGBColor(100, 100, 100)
    p2.alignment = PP_ALIGN.CENTER
    
    # Authors
    txBox3 = slide.shapes.add_textbox(Emu(457200), Emu(3155306), Emu(8686800), Emu(1256754))
    tf3 = txBox3.text_frame
    tf3.word_wrap = True
    authors = [
        "by",
        "Karthik Babu (RA2311053010001)",
        "Megha Sara Baiju (RA2311053010002)",
        "Yempara Neeharika (RA2311053010003)"
    ]
    for i, line in enumerate(authors):
        p = tf3.add_paragraph() if i > 0 else tf3.paragraphs[0]
        p.text = line
        p.font.size = Pt(20) if i > 0 else Pt(18)
        p.font.name = 'Times New Roman'
        p.alignment = PP_ALIGN.CENTER
        
    # Guide
    txBox4 = slide.shapes.add_textbox(Emu(457200), Emu(5003520), Emu(8686800), Emu(1200000))
    tf4 = txBox4.text_frame
    tf4.word_wrap = True
    guide_lines = [
        "Guide:",
        "S. Diana Emerald Aasha",
        "Assistant Professor, Department of ECE",
        datetime.datetime.now().strftime("%B %d, %Y")
    ]
    for i, line in enumerate(guide_lines):
        p = tf4.add_paragraph() if i > 0 else tf4.paragraphs[0]
        p.text = line
        p.font.size = Pt(18)
        p.font.name = 'Times New Roman'
        if i == 1: p.font.bold = True
        p.alignment = PP_ALIGN.CENTER

def add_content_slide(title_text, slide_num):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    add_common_elements(slide, slide_num)
    
    # Title
    txBox = slide.shapes.add_textbox(Emu(577519), Emu(592070), Emu(7132320), Emu(600000))
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = title_text
    p.font.size = Pt(32)
    p.font.bold = True
    p.font.name = 'Times New Roman'
    p.font.color.rgb = TITLE_COLOR
    
    return slide

def add_bullets(slide, items, left=548640, top=1322172, width=8961120, height=5632311, pt_size=20):
    txBox = slide.shapes.add_textbox(Emu(left), Emu(top), Emu(width), Emu(height))
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.add_paragraph() if i > 0 else tf.paragraphs[0]
        p.text = str(item).replace('• ', '')
        if item.startswith('• '):
            p.level = 1
        elif item.startswith('    • '):
            p.level = 2
        else:
            p.level = 0
            if i > 0: p.space_before = Pt(10)
        p.font.size = Pt(pt_size)
        p.font.name = 'Times New Roman'
    return txBox

# 1
add_title_slide()

# 2
slide = add_content_slide("Introduction", 2)
add_bullets(slide, [
    "• IoT devices generate continuous network traffic with device-specific communication behaviour.",
    "• Different IoT device types naturally produce different traffic patterns such as packet timing, packet rate and packet size.",
    "• Abnormal communication behaviour may indicate malfunction, overload, misconfiguration or potentially suspicious activity.",
    "• Payload inspection is not always suitable for network monitoring, so behavioural metadata provides a useful alternative.",
    "• Machine-learning-based anomaly detection can identify deviations from learned normal behaviour without requiring labelled attack data for every possible attack.",
    "• This project develops a software-only experimental framework that simulates IoT traffic, learns normal behavioural patterns and detects controlled anomalous behaviour."
], pt_size=22)

# 3
slide = add_content_slide("Problem Statement & Motivation", 3)
add_bullets(slide, [
    "Problem Statement",
    "• IoT devices exhibit different communication behaviours, making a single fixed traffic threshold unsuitable for all devices.",
    "• Manually identifying abnormal traffic from large numbers of observations is difficult.",
    "• Labelled attack datasets may not represent every possible abnormal behaviour.",
    "• A lightweight anomaly-detection approach is required to identify deviations from device-specific normal behaviour.",
    "Motivation",
    "• Develop a controlled software-only IoT network-security experiment.",
    "• Model different IoT device communication behaviours.",
    "• Learn normal behaviour independently for each device profile.",
    "• Detect statistically unusual communication patterns using unsupervised machine learning.",
    "• Provide interpretable results through a database-backed dashboard."
], pt_size=18)

# 4
slide = add_content_slide("Objectives", 4)
add_bullets(slide, [
    "1. Develop software-defined IoT traffic profiles representing different communication behaviours.",
    "2. Generate controlled normal IoT traffic using Python-based simulation.",
    "3. Extract behavioural features from sequential traffic windows.",
    "4. Learn device-specific normal behaviour using Isolation Forest.",
    "5. Generate controlled anomalous behaviour scenarios and evaluate the detector.",
    "6. Store traffic, feature windows and prediction results in SQLite.",
    "7. Develop a Streamlit dashboard for visualization, analysis and evidence-based interpretation."
], pt_size=22)

# 5
slide = add_content_slide("Literature Survey", 5)
table_shape = slide.shapes.add_table(7, 3, Emu(548640), Emu(1322172), Emu(8961120), Emu(4000000))
table = table_shape.table
table.columns[0].width = Emu(1500000)
table.columns[1].width = Emu(2500000)
table.columns[2].width = Emu(4961120)
headers = ["Authors & Year", "Paper Title / Topic", "Inference / Limitation / Relevance"]
for col_idx, h in enumerate(headers):
    cell = table.cell(0, col_idx)
    cell.text = h
    cell.text_frame.paragraphs[0].font.bold = True
    cell.text_frame.paragraphs[0].font.size = Pt(16)
    cell.text_frame.paragraphs[0].font.name = 'Times New Roman'
rows = [
    ["Kolias et al. (2016)", "Intrusion Detection in 802.11 Networks / AWID", "Provides a recognised Wi-Fi intrusion-detection benchmark and demonstrates the importance of network-level traffic analysis."],
    ["Sivanathan et al. (2019)", "Classifying IoT Devices in Smart Environments", "Shows that IoT devices exhibit distinguishable traffic characteristics, supporting device-specific behavioural modelling."],
    ["Meidan et al. (2018)", "N-BaIoT", "Demonstrates behavioural anomaly detection for IoT devices using machine learning."],
    ["Neto et al. (2023)", "CICIoT2023", "Provides a large-scale IoT security benchmark but uses richer traffic features than our controlled software simulation."],
    ["Liu, Ting & Zhou (2008)", "Isolation Forest", "Provides the theoretical foundation for our unsupervised anomaly detector."],
    ["Kim & Kim (2024)", "Anomaly Detection in Imbalanced Encrypted Traffic", "Supports the feasibility of metadata-based anomaly detection when payload information is limited."]
]
for r_idx, row_data in enumerate(rows):
    for c_idx, cell_data in enumerate(row_data):
        cell = table.cell(r_idx+1, c_idx)
        cell.text = cell_data
        cell.text_frame.paragraphs[0].font.size = Pt(14)
        cell.text_frame.paragraphs[0].font.name = 'Times New Roman'

# 6
slide = add_content_slide("Research Gap", 6)
add_bullets(slide, [
    "Existing Research",
    "• Wi-Fi intrusion datasets, IoT traffic classification",
    "• Machine-learning-based intrusion detection",
    "• Unsupervised anomaly detection & encrypted traffic analysis",
    "Identified Gaps",
    "• Many existing studies depend on large public datasets or specific attack labels.",
    "• Device-specific behavioural differences need to be considered when detecting anomalies.",
    "• Complex datasets may contain features that are not necessary for a lightweight experimental system.",
    "• There is scope for a simple, reproducible software-only framework that connects traffic simulation, feature extraction, anomaly detection, database storage and visual analysis.",
    "Our Gap Addressed",
    "• Software-defined IoT traffic profiles and device-specific normal baselines.",
    "• Lightweight Isolation Forest anomaly detection and controlled anomalous-behaviour evaluation.",
    "• Feature-level evidence with SQLite + Streamlit integration."
], pt_size=18)

# 7
slide = add_content_slide("Proposed System", 7)
add_bullets(slide, [
    "1. Software-defined IoT profiles",
    "2. Normal traffic simulation",
    "3. Feature extraction",
    "4. Device-specific baseline learning",
    "5. Isolation Forest detection",
    "6. Controlled anomalous-behaviour testing",
    "7. Evidence storage",
    "8. Dashboard visualization"
], pt_size=20, left=548640, top=1322172, width=4000000)

add_bullets(slide, [
    "Software-Defined IoT Profiles:",
    "• Temperature Sensor",
    "• Smart Light",
    "• Smart Plug",
    "• Motion Sensor",
    "• Camera-like Traffic Generator"
], pt_size=20, left=5000000, top=1322172, width=4500000)

txBox = slide.shapes.add_textbox(Emu(548640), Emu(5500000), Emu(8961120), Emu(1500000))
tf = txBox.text_frame
tf.word_wrap = True
p = tf.paragraphs[0]
p.text = "Important Note: The system is a controlled software-only experimental framework; the simulated anomalous behaviour represents statistical deviation and is not claimed to be a confirmed real-world cyberattack."
p.font.size = Pt(18)
p.font.bold = True
p.font.italic = True
p.font.name = 'Times New Roman'
p.font.color.rgb = RGBColor(128, 0, 0)

# 8
slide = add_content_slide("System Architecture / Methodology", 8)
arch_text = """5 Software-defined IoT Profiles
       ↓
Traffic Simulation
       ↓
Raw Traffic Observations
       ↓
10-Packet Sequential Windows
       ↓
Feature Extraction
       ↓
5 Behavioural Features
       ↓
Device-Specific Normal Training
       ↓
Isolation Forest
       ↓
Prediction
       ↓
Anomaly Score + Evidence
       ↓
SQLite Database
       ↓
Streamlit Dashboard"""
txBox = slide.shapes.add_textbox(Emu(548640), Emu(1300000), Emu(4000000), Emu(5500000))
tf = txBox.text_frame
p = tf.paragraphs[0]
p.text = arch_text
p.font.size = Pt(15)
p.font.name = 'Courier New'
p.font.bold = True

add_bullets(slide, [
    "The 5 Behavioural Features:",
    "• Mean IAT",
    "• IAT Standard Deviation",
    "• Packet Rate",
    "• Mean Packet Size",
    "• Packet Size Standard Deviation",
    "",
    "Note: Node_ID, Node_Type and Window_ID are identifiers/metadata and are NOT used as ML behavioural features."
], pt_size=18, left=5000000, top=1300000, width=4500000)

# 9
slide = add_content_slide("Implementation", 9)
add_bullets(slide, [
    "A. Traffic Simulation",
    "• Python-based software simulation",
    "• Five IoT traffic profiles",
    "• Controlled packet timing and packet-size behaviour",
    "• 9,073 simulated traffic observations",
    "",
    "B. Feature Engineering",
    "• 10-packet sequential windows",
    "• Five behavioural features",
    "• Separate device-specific feature sets"
], pt_size=18, left=548640, top=1322172, width=4400000)

add_bullets(slide, [
    "C. Machine Learning",
    "• Isolation Forest",
    "• One model per software-defined IoT profile",
    "• 80/20 normal train-test split",
    "• contamination = 0.05 | random_state = 42",
    "",
    "D. Database & Dashboard",
    "• SQLite database (Dataset/run separation)",
    "• Streamlit dashboard",
    "• Interactive feature and prediction analysis"
], pt_size=18, left=5000000, top=1322172, width=4500000)

# 10
slide = add_content_slide("Results and Discussion", 10)
add_bullets(slide, [
    "Final Evaluation Metrics:",
    "• Normal feature windows: 905",
    "• Controlled anomaly feature windows: 904",
    "• Detected anomalous windows: 886",
    "• Missed anomalous windows: 18",
    "• Detection Rate: 98.01% (886 / 904 × 100)",
    "• Normal-test false positive rate: 8.20%",
    "• Isolation Forest: contamination = 0.05",
    "",
    "Node-Wise Detection:",
    "• Temperature Sensor: 100%",
    "• Smart Light: 100%",
    "• Smart Plug: 94.27%",
    "• Motion Sensor: 79.55%",
    "• Camera-like Traffic Generator: 100%"
], pt_size=16, left=548640, top=1322172, width=4400000)

add_bullets(slide, [
    "Discussion:",
    "• The selected contamination setting reduced the normal-test false-positive rate from 24.59% to 8.20%.",
    "• Detection decreased only slightly from 99.23% to 98.01%.",
    "• This trade-off motivated the selection of contamination = 0.05.",
    "• Motion Sensor showed the lowest detection rate because its legitimate burst behaviour creates greater overlap with anomalous burst patterns.",
    "• The results demonstrate feasibility on controlled synthetic traffic, but they do not represent real-world attack detection accuracy."
], pt_size=16, left=5000000, top=1322172, width=4500000)

# 11
slide = add_content_slide("Conclusion", 11)
add_bullets(slide, [
    "• Developed a software-only framework for IoT Wi-Fi behavioural anomaly detection.",
    "• Simulated five different IoT communication profiles with distinct traffic characteristics.",
    "• Extracted five behavioural features from sequential traffic windows.",
    "• Trained device-specific Isolation Forest models using normal behaviour.",
    "• Evaluated the detector using controlled synthetic anomalous behaviour.",
    "• Achieved 98.01% detection of controlled anomalous windows with an 8.20% normal-test false-positive rate.",
    "• Integrated SQLite for experiment/result storage and Streamlit for interactive analysis.",
    "",
    "The system demonstrates a reproducible academic approach for detecting statistical deviations in software-simulated IoT traffic."
], pt_size=20)

# 12
slide = add_content_slide("Future Scope", 12)
add_bullets(slide, [
    "• Validate the framework using traffic generated by real IoT devices.",
    "• Integrate real Wi-Fi/network captures where legally and technically feasible.",
    "• Expand device profiles and traffic scenarios.",
    "• Evaluate additional unsupervised and semi-supervised algorithms.",
    "• Investigate adaptive baseline learning for changing device behaviour.",
    "• Add explainable anomaly evidence and improved risk scoring.",
    "• Evaluate performance using larger and more diverse real-world datasets."
], pt_size=22)

# 13
slide = add_content_slide("References", 13)
add_bullets(slide, [
    "[1] Kolias et al., \"Intrusion Detection in 802.11 Networks / AWID\", 2016.",
    "[2] Sivanathan et al., \"Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics\", 2019.",
    "[3] Meidan et al., \"N-BaIoT\", 2018.",
    "[4] Neto et al., \"CICIoT2023\", 2023.",
    "[5] Liu, Ting & Zhou, \"Isolation Forest\", 2008.",
    "[6] Kim & Kim, \"Anomaly Detection in Imbalanced Encrypted Traffic with Few Packet Metadata-Based Feature Extraction\", 2024."
], pt_size=20)

prs.save("AI_Assisted_IoT_Anomaly_Detection_Review2_Updated.pptx")
print("Saved PPTX successfully!")
