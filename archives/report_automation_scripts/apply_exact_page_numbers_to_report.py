"""
Apply Exact Verified Page Numbers to Table 0 (TOC), Table 1 (LOT), and Table 2 (LOF)
in IoT_Network_Guard_Final_Project_Report.docx.
"""

import docx

doc_path = "IoT_Network_Guard_Final_Project_Report.docx"
doc = docx.Document(doc_path)

# Verified Exact Page Map from Word Repagination
toc_exact_pages = {
    "ABSTRACT": "iii",
    "LIST OF TABLES": "vi",
    "LIST OF FIGURES": "vii",
    "1 INTRODUCTION": "1",
    "1.1 PROBLEM STATEMENT": "1",
    "1.1.1 Background": "1",
    "1.1.2 Motivation": "2",
    "1.2 OBJECTIVES": "3",
    "1.2.1 Scope of the Work": "4",
    "1.3 OUTLINE OF REPORT": "5",
    "2 LITERATURE REVIEW": "6",
    "2.1 RELATED WORK": "6",
    "2.1.1 IoT Network Security and Wi-Fi Vulnerabilities": "6",
    "2.1.2 Machine Learning and Anomaly Detection in Network Traffic": "7",
    "2.1.3 Behavioral Profiling and Multi-Dimensional Feature Analysis": "8",
    "2.1.4 Comparison of Existing Intrusion Detection Systems": "8",
    "2.1.5 Research Gaps Addressed by the Proposed System": "9",
    "2.2 MATHEMATICAL BACKGROUND": "10",
    "2.2.1 Traffic Feature Formulations": "10",
    "2.2.2 Dual Isolation Forest Theoretical Formulations": "11",
    "2.2.3 Performance and Classification Evaluation Metrics": "12",
    "3 SYSTEM DESIGN AND METHODOLOGY": "14",
    "3.1 PROPOSED SYSTEM": "14",
    "3.1.1 Overall System Architecture": "14",
    "3.1.2 Hardware and Sensor Architecture": "16",
    "3.1.3 Software Requirements and Technology Stack": "18",
    "3.2 IMPLEMENTATION": "19",
    "3.2.1 Packet Capture and Traffic Window Generation": "19",
    "3.2.2 Dual-Detector Machine Learning Pipeline": "20",
    "3.2.3 Deterministic Cyberattack Signature Engine": "22",
    "3.2.4 Local Persistence and Cloud Synchronization Architecture": "23",
    "3.2.5 Test Setup and Verification Methodology": "25",
    "4 RESULTS AND DISCUSSION": "27",
    "4.1 RESULTS": "27",
    "4.1.1 Machine Learning Model Evaluation": "27",
    "4.1.2 Attack Detection Performance Across Threat Categories": "30",
    "4.1.3 Hardware Sensor Telemetry and Latency Analysis": "31",
    "4.1.4 Cloud Synchronization and Verification Audit": "33",
    "4.2 DISCUSSION": "33",
    "4.2.1 Comparative Performance and Architectural Advantages": "34",
    "4.2.2 Real-World Operational Limitations and Threats to Validity": "34",
    "5 CONCLUSION": "36",
    "5.1 REVIEW": "36",
    "5.2 CONCLUSIONS": "36",
    "5.3 RECOMMENDATIONS FOR FUTURE WORK": "37",
    "REFERENCES": "39",
    "APPENDICES": "41",
    "APPENDIX 1  LISTING OF PROGRAMS": "41",
    "APPENDIX 2  RAW EXPERIMENTAL DATA": "43",
    "PUBLICATION DETAILS": "45"
}

lot_exact_pages = {
    "Table 2.1": "8",
    "Table 2.2": "13",
    "Table 3.1": "17",
    "Table 3.2": "18",
    "Table 3.3": "24",
    "Table 4.1": "28",
    "Table 4.2": "31",
    "Table 4.3": "32",
    "Table A 2.1": "43"
}

lof_exact_pages = {
    "Figure 3.1": "15",
    "Figure 3.2": "16",
    "Figure 3.3": "19",
    "Figure 3.4": "21",
    "Figure 3.5": "23",
    "Figure 4.1": "30",
    "Figure 4.2": "33"
}

# 1. Update Table 0 (TOC)
t0 = doc.tables[0]
print(f"Updating Table 0 ({len(t0.rows)} rows)...")
for r in t0.rows[1:]:
    s_no = r.cells[0].text.strip()
    title = r.cells[1].text.strip()
    key = f"{s_no} {title}".strip()
    
    if key in toc_exact_pages:
        r.cells[2].text = toc_exact_pages[key]
    elif title in toc_exact_pages:
        r.cells[2].text = toc_exact_pages[title]
    else:
        print(f"Warning: Key not found in toc_exact_pages: '{key}' / '{title}'")

# 2. Update Table 1 (LOT)
t1 = doc.tables[1]
print(f"Updating Table 1 ({len(t1.rows)} rows)...")
for r in t1.rows[1:]:
    caption = r.cells[1].text.strip()
    matched = False
    for k, p in lot_exact_pages.items():
        if caption.startswith(k):
            r.cells[2].text = p
            matched = True
            break
    if not matched:
        print(f"Warning: Caption not matched in lot_exact_pages: '{caption}'")

# 3. Update Table 2 (LOF)
t2 = doc.tables[2]
print(f"Updating Table 2 ({len(t2.rows)} rows)...")
for r in t2.rows[1:]:
    caption = r.cells[1].text.strip()
    matched = False
    for k, p in lof_exact_pages.items():
        if caption.startswith(k):
            r.cells[2].text = p
            matched = True
            break
    if not matched:
        print(f"Warning: Caption not matched in lof_exact_pages: '{caption}'")

doc.save(doc_path)
print("Saved document with exact verified page numbers!")
