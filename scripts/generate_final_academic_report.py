"""
Master Script: Generate Complete Submission-Ready Academic Project Report
Target Document: IoT_Network_Guard_Final_Project_Report.docx
Official Template Base: Project_Report_CCNS.docx

Institution: SRM Institute of Science and Technology, Kattankulathur
College: College of Engineering and Technology
Department: Department of Electronics and Communication Engineering
Course: 21ECC402P – Computer Communication and Network Security
Academic Year: 2026–2027 (ODD)
Project Title: AI-Assisted IoT Wi-Fi Anomaly Detection
Application: IoT Network Guard — Dual-Detector SOC Console

Project Team Members:
1. B. Karthik Babu (Reg. No. RA2311053010001)
2. Megha Sara Baiju (Reg. No. RA2311053010002)
3. Yempara Neeharika (Reg. No. RA2311053010003)

Project Guide / Supervisor:
S. Diana Emerald Aasha, Assistant Professor, Department of ECE

Review 3 Evaluators:
1. Dr. R. Monika, Assistant Professor, Department of ECE
2. Dr. K. Kalimuthu, Professor, Department of ECE

Publication Status: Not Applicable / Nil
"""

import os
import shutil
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

BASE_TEMPLATE = "Project_Report_CCNS.docx"
TARGET_DOCX = "IoT_Network_Guard_Final_Project_Report.docx"
FIG_DIR = os.path.abspath("scratch/report_figures")


def set_cell_border(cell, top=None, bottom=None, left=None, right=None):
    """Sets borders for a single cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = parse_xml(f'<w:tcBorders {nsdecls("w")}/>')
    borders = {'top': top, 'bottom': bottom, 'left': left, 'right': right}
    for border_name, border_style in borders.items():
        if border_style:
            tag = f'<w:{border_name} {nsdecls("w")} w:val="{border_style.get("val", "single")}" w:sz="{border_style.get("sz", "4")}" w:space="0" w:color="{border_style.get("color", "000000")}"/>'
            tcBorders.append(parse_xml(tag))
        else:
            tag = f'<w:{border_name} {nsdecls("w")} w:val="none"/>'
            tcBorders.append(parse_xml(tag))
    tcPr.append(tcBorders)


def set_cell_shading(cell, color_hex="E7E6E6"):
    """Sets background shading of a cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
    tcPr.append(shd)


def set_cell_margins(cell, top=60, bottom=60, left=100, right=100):
    """Sets cell padding in dxa."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)


def add_heading_1(doc, text):
    """Adds Chapter Heading (Heading 1 style, centered, uppercase)."""
    p = doc.add_paragraph(text, style='Heading 1')
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    return p


def add_heading_2(doc, text):
    """Adds Section Heading (Heading 2 style, bold, left-aligned)."""
    p = doc.add_paragraph(text, style='Heading 2')
    return p


def add_heading_3(doc, text):
    """Adds Subsection Heading (Heading 3 style, bold, left-aligned)."""
    p = doc.add_paragraph(text, style='Heading 3')
    return p


def add_body(doc, text):
    """Adds standard body paragraph (Body Text 2 style, justified, 1.5 line spacing)."""
    p = doc.add_paragraph(text, style='Body Text 2')
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    return p


def add_equation(doc, eq_text, eq_num):
    """Adds numbered equation with right-aligned equation number."""
    p = doc.add_paragraph(style='Equation Line')
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    # Tabs: equation centered, number right-aligned
    run_eq = p.add_run(f"\t\t{eq_text}\t\t{eq_num}")
    run_eq.font.name = 'Times New Roman'
    run_eq.font.italic = False
    return p


def add_custom_table(doc, caption_text, headers, rows_data, col_widths, alignments=None):
    """Adds a professionally formatted table with caption above it."""
    # Caption above table
    p_cap = doc.add_paragraph(style='Normal')
    p_cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
    run_cap = p_cap.add_run(caption_text)
    run_cap.font.name = 'Times New Roman'
    run_cap.font.size = Pt(11)
    run_cap.font.bold = True

    # Create table
    table = doc.add_table(rows=len(rows_data) + 1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    b_border = {'val': 'single', 'sz': '4', 'color': '000000'}

    # Header Row
    hdr_cells = table.rows[0].cells
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        set_cell_border(hdr_cells[i], top=b_border, bottom=b_border, left=b_border, right=b_border)
        set_cell_shading(hdr_cells[i], "E7E6E6")
        set_cell_margins(hdr_cells[i], top=80, bottom=80, left=100, right=100)
        p = hdr_cells[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in p.runs:
            run.font.name = 'Times New Roman'
            run.font.size = Pt(10)
            run.font.bold = True

    # Data Rows
    for r_idx, r_data in enumerate(rows_data):
        row_cells = table.rows[r_idx + 1].cells
        for c_idx, val in enumerate(r_data):
            row_cells[c_idx].text = str(val)
            set_cell_border(row_cells[c_idx], top=b_border, bottom=b_border, left=b_border, right=b_border)
            set_cell_margins(row_cells[c_idx], top=60, bottom=60, left=100, right=100)
            p = row_cells[c_idx].paragraphs[0]
            align = alignments[c_idx] if alignments and c_idx < len(alignments) else WD_ALIGN_PARAGRAPH.LEFT
            p.alignment = align
            for run in p.runs:
                run.font.name = 'Times New Roman'
                run.font.size = Pt(9.5)

    # Set column widths
    for row in table.rows:
        for idx, width in enumerate(col_widths):
            row.cells[idx].width = Inches(width)

    # Spacing after table
    p_sp = doc.add_paragraph(style='Normal')
    p_sp.paragraph_format.space_before = Pt(4)
    p_sp.paragraph_format.space_after = Pt(8)
    return table


def add_custom_figure(doc, img_name, caption_text, width_in=6.0):
    """Adds centered image followed by caption below."""
    img_path = os.path.join(FIG_DIR, img_name)
    if os.path.exists(img_path):
        p_img = doc.add_paragraph(style='Normal')
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img.paragraph_format.space_before = Pt(8)
        p_img.paragraph_format.space_after = Pt(4)
        run_img = p_img.add_run()
        run_img.add_picture(img_path, width=Inches(width_in))

    p_cap = doc.add_paragraph(style='Normal')
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after = Pt(12)
    run_cap = p_cap.add_run(caption_text)
    run_cap.font.name = 'Times New Roman'
    run_cap.font.size = Pt(11)
    run_cap.font.bold = True


def add_code_listing(doc, title, code_lines):
    """Adds a formatted monospace code block in single spacing."""
    p_t = doc.add_paragraph(style='Normal')
    p_t.paragraph_format.space_before = Pt(6)
    p_t.paragraph_format.space_after = Pt(2)
    r_t = p_t.add_run(title)
    r_t.font.name = 'Times New Roman'
    r_t.font.size = Pt(10.5)
    r_t.font.bold = True

    p_c = doc.add_paragraph(style='Reference Text')
    p_c.paragraph_format.space_before = Pt(2)
    p_c.paragraph_format.space_after = Pt(8)
    p_c.paragraph_format.line_spacing = 1.0

    run_c = p_c.add_run("\n".join(code_lines))
    run_c.font.name = 'Consolas'
    run_c.font.size = Pt(8.5)
    run_c.font.color.rgb = RGBColor(30, 41, 59)


def populate_toc_lot_lof(doc):
    """Populates Table 0 (TOC), Table 1 (LOT), and Table 2 (LOF) with initial structure."""
    b_border = {'val': 'single', 'sz': '4', 'color': '000000'}

    # 1. TABLE OF CONTENTS (Table 0)
    t0 = doc.tables[0]
    # Clear existing rows except header
    for r in t0.rows[1:][::-1]:
        r._tr.getparent().remove(r._tr)

    toc_entries = [
        ("", "ABSTRACT", "iii", 0),
        ("", "LIST OF TABLES", "vi", 0),
        ("", "LIST OF FIGURES", "vii", 0),
        ("1", "INTRODUCTION", "1", 0),
        ("1.1", "PROBLEM STATEMENT", "1", 300),
        ("1.1.1", "Background", "1", 600),
        ("1.1.2", "Motivation", "2", 600),
        ("1.2", "OBJECTIVES", "3", 300),
        ("1.2.1", "Scope of the Work", "4", 600),
        ("1.3", "OUTLINE OF REPORT", "5", 300),
        ("2", "LITERATURE REVIEW", "6", 0),
        ("2.1", "RELATED WORK", "6", 300),
        ("2.1.1", "IoT Network Security and Wi-Fi Vulnerabilities", "6", 600),
        ("2.1.2", "Machine Learning and Anomaly Detection in Network Traffic", "7", 600),
        ("2.1.3", "Behavioral Profiling and Multi-Dimensional Feature Analysis", "8", 600),
        ("2.1.4", "Comparison of Existing Intrusion Detection Systems", "8", 600),
        ("2.1.5", "Research Gaps Addressed by the Proposed System", "9", 600),
        ("2.2", "MATHEMATICAL BACKGROUND", "10", 300),
        ("2.2.1", "Traffic Feature Formulations", "10", 600),
        ("2.2.2", "Dual Isolation Forest Theoretical Formulations", "11", 600),
        ("2.2.3", "Performance and Classification Evaluation Metrics", "12", 600),
        ("3", "SYSTEM DESIGN AND METHODOLOGY", "14", 0),
        ("3.1", "PROPOSED SYSTEM", "14", 300),
        ("3.1.1", "Overall System Architecture", "14", 600),
        ("3.1.2", "Hardware and Sensor Architecture", "16", 600),
        ("3.1.3", "Software Requirements and Technology Stack", "18", 600),
        ("3.2", "IMPLEMENTATION", "19", 300),
        ("3.2.1", "Packet Capture and Traffic Window Generation", "19", 600),
        ("3.2.2", "Dual-Detector Machine Learning Pipeline", "20", 600),
        ("3.2.3", "Deterministic Cyberattack Signature Engine", "22", 600),
        ("3.2.4", "Local Persistence and Cloud Synchronization Architecture", "23", 600),
        ("3.2.5", "Test Setup and Verification Methodology", "25", 600),
        ("4", "RESULTS AND DISCUSSION", "27", 0),
        ("4.1", "RESULTS", "27", 300),
        ("4.1.1", "Machine Learning Model Evaluation", "27", 600),
        ("4.1.2", "Attack Detection Performance Across Threat Categories", "30", 600),
        ("4.1.3", "Hardware Sensor Telemetry and Latency Analysis", "31", 600),
        ("4.1.4", "Cloud Synchronization and Verification Audit", "33", 600),
        ("4.2", "DISCUSSION", "34", 300),
        ("4.2.1", "Comparative Performance and Architectural Advantages", "34", 600),
        ("4.2.2", "Real-World Operational Limitations and Threats to Validity", "34", 600),
        ("5", "CONCLUSION", "36", 0),
        ("5.1", "REVIEW", "36", 300),
        ("5.2", "CONCLUSIONS", "36", 300),
        ("5.3", "RECOMMENDATIONS FOR FUTURE WORK", "37", 300),
        ("", "REFERENCES", "39", 0),
        ("", "APPENDICES", "41", 0),
        ("", "APPENDIX 1  LISTING OF PROGRAMS", "41", 300),
        ("", "APPENDIX 2  RAW EXPERIMENTAL DATA", "43", 300),
        ("", "PUBLICATION DETAILS", "45", 0)
    ]

    for s_no, title, page, ind in toc_entries:
        row = t0.add_row()
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.text = s_no
        c1.text = title
        c2.text = page
        for c in (c0, c1, c2):
            set_cell_border(c, top=b_border, bottom=b_border, left=b_border, right=b_border)
            set_cell_margins(c, top=40, bottom=40, left=100, right=100)
            p = c.paragraphs[0]
            p.style = 'ListText'
        c0.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        c2.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        p1 = c1.paragraphs[0]
        p1.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p1.paragraph_format.left_indent = Pt(ind / 20.0)
        c0.width = Inches(0.694)
        c1.width = Inches(4.31)
        c2.width = Inches(0.903)

    # 2. LIST OF TABLES (Table 1)
    t1 = doc.tables[1]
    for r in t1.rows[1:][::-1]:
        r._tr.getparent().remove(r._tr)

    lot_entries = [
        ("1", "Table 2.1  Comparison of Existing Network Security and IDS Paradigms", "8"),
        ("2", "Table 2.2  Mathematical Feature Inventory and Operational Formulation", "13"),
        ("3", "Table 3.1  Hardware Components and Environmental Sensing Specifications", "17"),
        ("4", "Table 3.2  Software Stack, Frameworks, and Deployment Dependencies", "18"),
        ("5", "Table 3.3  Database Schema and Dual-Tier Persistence Architecture", "24"),
        ("6", "Table 4.1  Dual-Detector Machine Learning Performance on Benchmark Scenarios", "28"),
        ("7", "Table 4.2  Attack Classification Performance Across Five Threat Categories", "31"),
        ("8", "Table 4.3  System Latency, Ingestion Throughput, and Resource Utilization", "32"),
        ("9", "Table A 2.1  Representative Raw Experimental Telemetry and Traffic Feature Windows", "43")
    ]

    for s_no, title, page in lot_entries:
        row = t1.add_row()
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.text = s_no
        c1.text = title
        c2.text = page
        for c in (c0, c1, c2):
            set_cell_border(c, top=b_border, bottom=b_border, left=b_border, right=b_border)
            set_cell_margins(c, top=40, bottom=40, left=100, right=100)
            p = c.paragraphs[0]
            p.style = 'ListText'
        c0.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        c2.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        c1.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT
        c0.width = Inches(0.694)
        c1.width = Inches(4.31)
        c2.width = Inches(0.903)

    # 3. LIST OF FIGURES (Table 2)
    t2 = doc.tables[2]
    for r in t2.rows[1:][::-1]:
        r._tr.getparent().remove(r._tr)

    lof_entries = [
        ("1", "Figure 3.1  Overall Architecture of the Proposed IoT Network Guard System", "15"),
        ("2", "Figure 3.2  ESP32 Hardware and Sensor Telemetry Architecture", "16"),
        ("3", "Figure 3.3  Network Traffic Capture and 1-Second Feature Extraction Workflow", "19"),
        ("4", "Figure 3.4  Dual-Detector Machine Learning Inference Architecture", "21"),
        ("5", "Figure 3.5  Local Sovereign Storage and Cloud Synchronization Architecture", "23"),
        ("6", "Figure 4.1  Confusion Matrices for Evaluated Machine Learning Detector Architectures", "30"),
        ("7", "Figure 4.2  Precision-Recall Curves and Anomaly Score Response Timeline", "33")
    ]

    for s_no, title, page in lof_entries:
        row = t2.add_row()
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.text = s_no
        c1.text = title
        c2.text = page
        for c in (c0, c1, c2):
            set_cell_border(c, top=b_border, bottom=b_border, left=b_border, right=b_border)
            set_cell_margins(c, top=40, bottom=40, left=100, right=100)
            p = c.paragraphs[0]
            p.style = 'ListText'
        c0.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        c2.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        c1.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.LEFT
        c0.width = Inches(0.694)
        c1.width = Inches(4.31)
        c2.width = Inches(0.903)


def populate_abstract(doc):
    """Replaces placeholder paragraphs in Section 0 with final comprehensive Abstract."""
    # Para 1 is 'ABSTRACT' (Front Heading). Paras 2, 3, 4, 5 are the Abstract Text.
    abstract_paras = [
        "The proliferation of Internet of Things (IoT) devices in contemporary residential, commercial, and industrial wireless local area networks (WLANs) has introduced critical cybersecurity vulnerabilities. Constrained by limited computational capabilities, memory, and energy budgets, commercial IoT endpoints frequently lack integrated endpoint security agents and rely on unauthenticated IEEE 802.11 management frames and unencrypted communication protocols. Consequently, these environments are highly susceptible to malicious intrusions, including volumetric Denial-of-Service (DoS), unauthorized reconnaissance scanning, Address Resolution Protocol (ARP) spoofing, Wi-Fi deauthentication flooding, and replay attacks. Traditional enterprise intrusion detection systems (IDS) relying on deep packet inspection impose unacceptable processing overhead, while standard machine learning anomaly detectors exhibit severe false alarm rates during quiescent periods when single-packet telemetry yields undefined inter-arrival times. This project addresses the urgent need for a lightweight, edge-deployable, false-alarm-resilient network intrusion detection architecture specifically tailored for resource-constrained IoT Wi-Fi networks.",

        "To overcome these fundamental limitations, this report presents the design, mathematical formulation, implementation, and empirical validation of IoT Network Guard — a dual-detector Security Operations Center (SOC) architecture. The proposed framework integrates physical environmental sensing via an ESP32 microcontroller (capturing DHT11 temperature/humidity and HC-SR501 passive infrared motion telemetry) with passive promiscuous IEEE 802.11 packet interception executed through a non-disruptive TShark packet extraction pipeline. Network traffic is parsed into deterministic 1-second temporal feature windows. An innovative Dual Isolation Forest architecture is formulated with explicit mathematical gating: a Primary Detector analyzes volumetric and packet size distributions across all windows, whereas a Secondary Timing Detector analyzes inter-arrival time (IAT) dispersion strictly when window packet counts satisfy N ≥ 3 (ensuring valid degrees of freedom for sample variance). Windows with N < 3 bypass timing evaluation, completely eliminating spurious alarms on quiescent traffic. To provide actionable defensive intelligence, a deterministic cyberattack engine classifies detected anomalies into five distinct threat categories with structured evidence telemetry. Local data persistence is established using high-concurrency SQLite with Write-Ahead Logging (WAL) and a durable 4-tier priority outbox queue, which synchronizes over TLS 1.3 to a cloud-hosted Supabase PostgreSQL 17.6 database supporting dual operator SOC consoles.",

        "The proposed architecture was evaluated across synthetic benchmark scenarios, captured real-world wireless network traces, and controlled cyberattack injection experiments. In synthetic scenario benchmarking, the existing naive 5-feature Isolation Forest baseline suffered a disastrous 90.0% false alarm rate (18 false positives out of 20 quiescent windows) with an overall precision of 53.85%, recall of 35.00%, and F1-score of 0.4242. In contrast, the proposed Dual-Detector architecture achieved 100.0% precision, 100.0% recall, and an F1-score of 1.000 across all 130 evaluation windows, detecting 100% of high-rate bursts, jumbo payload corruptions, and erratic IAT dispersions while maintaining an absolute 0.0% false alarm rate on normal and quiescent single-packet windows. Empirical cyberattack validation confirmed 100% detection sensitivity across all five attack categories with high confidence ratings (0.85 to 0.95). In end-to-end performance benchmarking, the total feature extraction and dual inference pipeline executed within 2.65 ms per 1-second window on a standard host, utilizing less than 4% CPU overhead and preserving complete edge sovereignty during network disconnections.",

        "The results demonstrate that decoupling volumetric analysis from sample-gated timing jitter successfully resolves the classical sensitivity-specificity dilemma in edge IoT network security. By providing real-time, explainable anomaly detection, robust physical-network telemetry correlation, resilient local storage, and privacy-preserving cloud synchronization, IoT Network Guard delivers a commercially viable, academically rigorous defense system that significantly enhances the defensive posture of modern IoT deployments."
    ]

    for idx, text in enumerate(abstract_paras):
        p = doc.paragraphs[idx + 2]
        p.text = text
        p.style = 'Abstract Text'
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY


def build_full_report():
    print("Step 1: Copying base template...")
    shutil.copyfile(BASE_TEMPLATE, TARGET_DOCX)
    doc = docx.Document(TARGET_DOCX)

    print("Step 2: Cleaning placeholder elements from Section 1...")
    # Remove tables 3 to 7 (reverse order)
    for t in doc.tables[3:][::-1]:
        t._element.getparent().remove(t._element)

    # Remove paragraphs after paragraph 12 (reverse order)
    for p in doc.paragraphs[13:][::-1]:
        p._element.getparent().remove(p._element)

    print("Step 3: Populating preliminary pages...")
    populate_abstract(doc)
    populate_toc_lot_lof(doc)

    print("Step 4: Writing Chapter 1 — Introduction...")
    add_heading_1(doc, "CHAPTER 1\nINTRODUCTION")
    add_body(doc, "The rapid proliferation of Internet of Things (IoT) technology has fundamentally transformed consumer, commercial, and industrial automation. Millions of smart devices—ranging from environmental monitoring sensors and automated home appliances to high-definition IP surveillance cameras and industrial supervisory control systems—are now permanently interconnected through IEEE 802.11 wireless local area networks (WLANs). While these pervasive wireless interconnections provide unprecedented operational convenience and monitoring efficiency, they simultaneously expose network infrastructures to severe security vulnerabilities. The inherent characteristics of IoT endpoints—specifically their severe hardware resource constraints, absence of standardized endpoint protection software, and reliance on unauthenticated wireless transmissions—render them highly attractive targets for malicious adversaries.")

    add_heading_2(doc, "1.1 PROBLEM STATEMENT")
    add_body(doc, "Wireless IoT infrastructures operate in shared, unguided radio frequency environments where physical perimeter defense is inherently impossible. In typical residential, enterprise, and educational campus deployments, IoT devices share 2.4 GHz and 5 GHz wireless spectrum with standard personal computing stations and mobile handhelds. However, unlike traditional enterprise workstations running commercial endpoint detection and response (EDR) software, resource-constrained IoT nodes cannot support cryptographically intensive protocols, runtime behavioral monitors, or local deep packet inspection agents. Consequently, contemporary IoT networks face an unprecedented duality of threats: subtle statistical deviations that degrade device availability and quality-of-service, alongside deterministic malicious cyberattacks that actively attempt network takeover, credential theft, and denial of service.")

    add_heading_3(doc, "1.1.1 Background")
    add_body(doc, "The IEEE 802.11 wireless standard was historically designed to prioritize open medium access and seamless station mobility over rigorous cryptographic authentication of management and control frames. Although the introduction of Wi-Fi Protected Access 2 (WPA2) and Wi-Fi Protected Access 3 (WPA3) established robust payload confidentiality and mutual authentication for user data frames, baseline 802.11 management frames—such as Beacon, Probe Request, Probe Response, Disassociation, and Deauthentication frames—frequently remain transmitted in plaintext without cryptographic integrity verification in legacy and low-cost IoT networks where 802.11w Protected Management Frames (PMF) are not strictly enforced.")
    add_body(doc, "Furthermore, IoT endpoints are characterized by highly predictable, periodic traffic dynamics. A smart environmental monitor or smart thermostat typically transmits sensor telemetry in concise, discrete bursts separated by extended intervals of radio silence. This predictable periodicity creates unique structural vulnerabilities: an adversary observing the radio spectrum can easily infer device operational states, inject fabricated packets that mimic legitimate traffic, execute spoofing attacks, or flood the access point with forged disassociation packets to forcibly disconnect target stations and capture cryptographic handshakes.")

    add_heading_3(doc, "1.1.2 Motivation")
    add_body(doc, "Traditional network intrusion detection systems (NIDS), such as Snort, Suricata, and Zeek, were engineered primarily for wired enterprise backbones where dedicated high-performance server hardware performs signature matching and deep packet inspection (DPI) against extensive vulnerability databases. In edge IoT deployments, this traditional paradigm fails due to three fundamental obstacles:")
    add_body(doc, "First, DPI imposes computational and memory footprints that are entirely incompatible with edge gateways and low-cost embedded hardware probes. Second, signature-based detection is inherently incapable of detecting zero-day behavioral anomalies, low-rate statistical deviations, or novel timing jitter attacks. Third, modern application payloads are increasingly protected by Transport Layer Security (TLS 1.3), rendering payload inspection blind without intrusive and computationally prohibitive man-in-the-middle (MitM) certificate termination.")
    add_body(doc, "To overcome the limitations of signature matching, contemporary researchers have proposed applying machine learning anomaly detection—particularly unsupervised tree-based algorithms such as Isolation Forest—to statistical traffic features (packet rates, byte volumes, and inter-arrival times). However, existing implementations suffer from a critical flaw: the quiescent single-packet false alarm paradox. In typical 1-second edge monitoring windows, quiescent IoT sensors frequently transmit exactly one packet. In such windows, inter-arrival time (IAT) is mathematically undefined, and naive median imputation forces the feature vector to deviate wildly from multi-packet baselines, generating catastrophic false positive rates (up to 90% in empirical benchmarks). This fatal operational flaw causes severe operator alert fatigue, rendering conventional machine learning anomaly detectors unusable in real-world Security Operations Centers (SOCs).")
    add_body(doc, "These challenges motivate the development of IoT Network Guard: an edge-native, dual-detector network security system that combines physical sensor telemetry with passive Wi-Fi interception, solves the quiescent false alarm paradox through mathematically gated dual Isolation Forests, provides deterministic threat classification, and maintains sovereign local persistence alongside cloud-synchronized SOC visualization.")

    add_heading_2(doc, "1.2 OBJECTIVES")
    add_body(doc, "The primary objective of this project is to research, design, mathematically formalize, implement, and validate an edge-deployable, dual-detector network security monitoring framework capable of real-time, false-alarm-resilient anomaly detection and deterministic cyberattack classification in IoT Wi-Fi networks. Specifically, the project sets out to achieve the following core technical milestones:")
    add_body(doc, "1. Design and deploy an edge-native physical sensor probe using an ESP32 microcontroller to acquire environmental telemetry (DHT11 temperature, relative humidity) and passive infrared (HC-SR501 PIR) motion events, correlating physical environment conditions with network activity.")
    add_body(doc, "2. Construct a high-performance, non-disruptive Wi-Fi packet capture and stream extraction pipeline based on TShark to slice live network traffic into synchronized 1-second temporal feature windows across monitored stations.")
    add_body(doc, "3. Formulate and implement a novel Dual Isolation Forest machine learning architecture with explicit mathematical sample gating: a Primary Detector evaluating volumetric and packet size features across all windows, and a Secondary Gated Timing Detector activated exclusively when window packet counts satisfy N ≥ 3, eliminating quiescent single-packet false alarms while achieving 100% recall on volumetric, payload, and timing anomalies.")
    add_body(doc, "4. Engineer a deterministic cyberattack signature classification engine capable of categorizing detected statistical anomalies into five explicit threat classes: Denial-of-Service (DoS) floods, Reconnaissance port scanning (vertical and horizontal sweeps), ARP/MAC spoofing, Wi-Fi deauthentication abuse, and replay attacks with explainable evidence output.")
    add_body(doc, "5. Implement a robust, edge-sovereign dual-tier storage architecture utilizing local SQLite in Write-Ahead Logging (WAL) mode paired with a durable 4-tier priority outbox queue, synchronizing via TLS 1.3 to a cloud-hosted Supabase PostgreSQL 17.6 database serving dual local and cloud SOC visualization consoles.")

    add_heading_3(doc, "1.2.1 Scope of the Work")
    add_body(doc, "The scope of this project encompasses the end-to-end design, implementation, and empirical testing of the proposed system within a controlled laboratory and live demonstration environment. The operational boundaries include:")
    add_body(doc, "• Network Standard: IEEE 802.11b/g/n wireless local area network traffic monitored on a dedicated mobile hotspot subnet (192.168.137.0/24) operating on 2.4 GHz (Channel 6).")
    add_body(doc, "• Hardware Ingestion: Hardware telemetry acquisition from an ESP32 Dev Module (NodeMCU-32S) via serial UART (COM6, 115200 baud, 8N1) running custom C++ FreeRTOS firmware.")
    add_body(doc, "• Passive Observation: Non-intrusive monitoring exclusively. The system strictly avoids active counter-measures (such as automated deauthentication jamming or disruptive packet injection) to maintain network stability and regulatory compliance.")
    add_body(doc, "• Privacy Protection: Cryptographic pseudonymization of device hardware MAC addresses and masking of sensitive payload parameters in all public-facing views.")
    add_body(doc, "• Attack Classes: In-depth evaluation across five specified attack classes: TCP/UDP Port Scans, ARP Spoofing, 802.11 Deauthentication Floods, Replay Injections, and Volumetric DoS Floods.")

    add_heading_2(doc, "1.3 OUTLINE OF REPORT")
    add_body(doc, "This report is structured into five comprehensive chapters, followed by academic references, technical appendices, and publication details:")
    add_body(doc, "Chapter 1 introduces the project, contextualizes the vulnerabilities of IoT Wi-Fi networks, defines the problem statement, details the core objectives and project scope, and outlines the report.")
    add_body(doc, "Chapter 2 presents an exhaustive review of related literature across IoT security, machine learning anomaly detection, and existing NIDS paradigms. It develops the rigorous mathematical formulations governing 1-second feature extraction, degrees-of-freedom constraints, Isolation Forest path lengths, anomaly scoring functions, and evaluation metrics.")
    add_body(doc, "Chapter 3 details the system design, block diagrams, hardware specifications, software dependencies, and step-by-step implementation methodology, including packet extraction, the gated dual-detector pipeline, the deterministic attack engine, and the durable cloud synchronization outbox.")
    add_body(doc, "Chapter 4 presents the experimental results obtained from synthetic benchmarking, cyberattack validation suites, hardware telemetry profiling, and latency audits. It provides an in-depth critical discussion of architectural advantages, comparative trade-offs, and real-world operational limitations.")
    add_body(doc, "Chapter 5 concludes the report by reviewing salient contributions, assessing objective fulfillment, and outlining concrete directions for future research and engineering enhancements.")

    doc.add_page_break()

    print("Step 5: Writing Chapter 2 — Literature Review...")
    add_heading_1(doc, "CHAPTER 2\nLITERATURE REVIEW")
    add_body(doc, "This chapter surveys contemporary academic literature in wireless network security, IoT vulnerability analysis, and machine learning-assisted intrusion detection. It identifies critical research gaps in existing architectures and establishes the rigorous mathematical foundation governing the traffic feature engineering, sample-gated dual-detector inference, and evaluation metrics implemented in this project.")

    add_heading_2(doc, "2.1 RELATED WORK")
    add_body(doc, "The rapid growth of the IoT ecosystem has catalyzed intensive research into automated security monitoring. This section reviews key foundational studies across wireless vulnerability analysis, machine learning algorithms for traffic anomaly detection, and comparative intrusion detection paradigms.")

    add_heading_3(doc, "2.1.1 IoT Network Security and Wi-Fi Vulnerabilities")
    add_body(doc, "Wireless network security has been an active domain of investigation since the initial formulation of IEEE 802.11. In foundational research, Diffie and Hellman [10] established the principles of asymmetric public-key cryptography that underpin modern network key exchanges. However, implementing robust public-key cryptography on ultra-low-power microcontrollers remains challenging due to severe arithmetic and battery constraints.")
    add_body(doc, "Kolias et al. [5] analyzed the weaponization of insecure IoT endpoints during the infamous Mirai botnet incidents, demonstrating that default credentials, exposed management ports (Telnet/SSH), and predictable network behaviors allow adversaries to assemble massive distributed denial-of-service (DDoS) botnets within minutes. In wireless local area networks, Kolias et al. highlighted that unauthenticated 802.11 management frames represent a chronic attack vector: adversaries can effortlessly forge deauthentication and disassociation frames to disrupt communication or isolate stations.")
    add_body(doc, "Scarfone and Mell [9] in the NIST Special Publication 800-94 established comprehensive guidelines for intrusion detection and prevention systems (IDPS). They categorized detection technologies into signature-based, anomaly-based, and stateful protocol analysis, emphasizing that signature systems are fundamentally incapable of addressing novel zero-day attack variants without pre-existing definition signatures.")

    add_heading_3(doc, "2.1.2 Machine Learning and Anomaly Detection in Network Traffic")
    add_body(doc, "To detect zero-day intrusions and subtle malicious behaviors, researchers increasingly leverage machine learning techniques. Chaabouni et al. [4] provided a comprehensive survey of learning techniques applied to IoT network security, categorizing approaches into supervised classification (Random Forests, Support Vector Machines, k-Nearest Neighbors) and unsupervised anomaly detection (Clustering, One-Class SVMs, and Isolation Forests). While supervised models achieve high accuracy on known benchmark datasets, they fail catastrophically when exposed to unobserved attack distributions.")
    add_body(doc, "Liu, Ting, and Zhou [1] introduced the Isolation Forest algorithm, revolutionizing unsupervised anomaly detection. Unlike density-based or distance-based anomaly detectors (such as Local Outlier Factor or DBSCAN) that incur quadratic O(n²) computational complexity, Isolation Forest exploits two fundamental quantitative properties of anomalies: they are few in number and possess attribute values functionally disparate from normal instances. By recursively partitioning feature space using completely random axis-aligned splits, anomalies are isolated near the root of binary isolation trees (iTrees) with significantly shorter path lengths. Liu et al. demonstrated that Isolation Forest exhibits linear time complexity O(t · ψ · log ψ), where t is tree count and ψ is subsampling size, making it exceptionally well-suited for edge embedded systems.")
    add_body(doc, "Al-Garadi et al. [12] and Al-Haija and Al-Dmour [2] examined hybrid deep learning frameworks (Convolutional Neural Networks and Long Short-Term Memory networks) for cyberattack classification. Although these deep architectures achieve superior pattern recognition on large-scale datasets, their multi-gigabyte memory footprints and extreme floating-point arithmetic demands render them entirely infeasible for edge gateways operating without dedicated GPU acceleration.")

    add_heading_3(doc, "2.1.3 Behavioral Profiling and Multi-Dimensional Feature Analysis")
    add_body(doc, "A critical challenge in machine learning-based NIDS lies in extracting informative, privacy-preserving statistical features from raw packet streams. Sivanathan et al. [6] conducted extensive multi-month empirical traffic profiling across 28 distinct IoT devices, establishing that IoT traffic exhibits distinct, highly repeatable behavioral signatures in packet arrival rates, packet length distributions, and inter-arrival time (IAT) variances.")
    add_body(doc, "Meidan et al. [7] developed N-BaIoT, demonstrating that network-based behavioral traffic profiling using deep autoencoders can successfully identify botnet infections across commercial smart devices. However, their architecture extracted features across multiple decaying temporal windows (100 ms to 1 minute), incurring substantial state memory buffering overhead on edge micro-routers.")
    add_body(doc, "Anthi et al. [3] proposed a multi-stage supervised architecture for smart home security, classifying normal traffic, identifying attack types, and isolating affected devices. However, Anthi et al. acknowledged that supervised training on specific device profiles fails when new devices join the network or when firmware updates modify legitimate packet transmission patterns.")

    add_heading_3(doc, "2.1.4 Comparison of Existing Intrusion Detection Systems")
    add_body(doc, "To contextualize the technical advantages of the proposed IoT Network Guard, Table 2.1 presents a comprehensive comparative evaluation across contemporary intrusion detection paradigms, analyzing computational complexity, edge suitability, quiescent false alarm resilience, stealth attack sensitivity, and cloud reliance.")

    # TABLE 2.1
    t2_1_headers = ["IDS Paradigm", "Representative Systems", "Detection Mechanism", "Edge Suitability", "Quiescent False Alarms", "Stealth Sensitivity"]
    t2_1_rows = [
        ["Signature NIDS", "Snort, Suricata", "DPI pattern matching against rule DB", "Low (CPU / RAM intensive)", "Very Low (deterministic rules)", "Poor (zero-day blind)"],
        ["Flow-Based NIDS", "Zeek, NetFlow", "Flow statistical summaries (IPFIX)", "Moderate (aggregation delay)", "Low (coarse aggregation)", "Low (averages short bursts)"],
        ["Deep Learning", "N-BaIoT, Kitsune", "Autoencoder / LSTM reconstruction error", "Very Low (GPU / TPU required)", "Moderate (threshold drift)", "High (complex non-linear)"],
        ["Single Isolation Forest", "Standard sklearn IF", "Single multi-feature tree ensemble", "High (O(n) tree evaluation)", "Disastrous (~90% on N=1)", "Moderate (bursts only)"],
        ["Proposed Dual-Detector", "IoT Network Guard", "Sample-gated dual Isolation Forests + deterministic rules", "Very High (<3 ms latency on edge)", "Zero (mathematical gating N≥3)", "Very High (volumetric + jitter)"]
    ]
    t2_1_widths = [1.1, 1.1, 1.6, 1.1, 1.1, 1.0]
    add_custom_table(doc, "Table 2.1  Comparison of Existing Network Security and IDS Paradigms",
                     t2_1_headers, t2_1_rows, t2_1_widths)

    add_heading_3(doc, "2.1.5 Research Gaps Addressed by the Proposed System")
    add_body(doc, "A critical synthesis of published literature reveals four unresolved research gaps in contemporary IoT security architectures:")
    add_body(doc, "1. The Quiescent Single-Packet False Alarm Paradox: When fixed temporal windows (such as 1-second intervals) are applied to intermittent IoT traffic, single-packet windows produce undefined inter-arrival times. Standard pipelines employing median or zero imputation distort feature geometry, causing single-feature Isolation Forests to falsely classify legitimate quiescent transmissions as high-severity anomalies.")
    add_body(doc, "2. Lack of Physical-Cyber Context Correlation: Existing NIDS operate exclusively at the network layer, completely detached from physical environmental context. Correlating hardware telemetry (temperature, humidity, motion events) with network bursts enables operators to verify whether unexpected traffic reflects physical environmental triggers or malicious cyberattacks.")
    add_body(doc, "3. Complete Cloud Ingestion Dependency: Commercial cloud-native IoT platforms route raw packet telemetry directly to cloud services. During WAN outages or network saturation attacks, these systems become entirely blind. An edge system must maintain sovereign local persistence and autonomous detection.")
    add_body(doc, "4. Black-Box Machine Learning Decisions: Standard machine learning anomaly detectors output uncalibrated scalar scores without contextual explanations. Operators cannot determine why an anomaly was flagged or what specific defensive actions should be initiated.")

    add_heading_2(doc, "2.2 MATHEMATICAL BACKGROUND")
    add_body(doc, "This section derives the mathematical equations governing the traffic feature extraction, degrees-of-freedom sample gating, Isolation Forest anomaly scoring, and quantitative evaluation metrics utilized throughout the implementation.")

    add_heading_3(doc, "2.2.1 Traffic Feature Formulations")
    add_body(doc, "Let W_k denote a continuous 1-second temporal observation window defined over the closed-open epoch time interval [t_k, t_k + T_w), where T_w = 1.0 second. Suppose N packets are intercepted during window W_k, with arrival timestamps {t_1, t_2, ..., t_N} satisfying t_k ≤ t_1 ≤ t_2 ≤ ... ≤ t_N < t_k + T_w, and corresponding packet frame lengths {L_1, L_2, ..., L_N} measured in bytes.")
    add_body(doc, "For any consecutive pair of intercepted packets, the packet Inter-Arrival Time (IAT), denoted by Δt_i, represents the elapsed temporal duration between arrivals and is defined in seconds by:")

    add_equation(doc, "Δt_i = t_i - t_{i-1},  for i ∈ {2, 3, ..., N}", "(2.1)")

    add_body(doc, "where t_i is the arrival epoch of the i-th packet in seconds. For N ≥ 2 packets, exactly N - 1 discrete inter-arrival time intervals exist. The mean inter-arrival time, denoted by μ_IAT, is defined in seconds as:")

    add_equation(doc, "μ_IAT = (1 / (N - 1)) · ∑_{i=2}^N Δt_i", "(2.2)")

    add_body(doc, "The dispersion of packet arrivals is quantified by the sample standard deviation of inter-arrival times, denoted by σ_IAT. Applying Bessel's correction to ensure an unbiased estimator of population variance, σ_IAT is defined in seconds by:")

    add_equation(doc, "σ_IAT = sqrt( (1 / (N - 2)) · ∑_{i=2}^N (Δt_i - μ_IAT)^2 )", "(2.3)")

    add_body(doc, "Crucially, inspecting Equation (2.3) reveals the fundamental degrees of freedom constraint: computing sample standard deviation requires dividing by (N - 1) - 1 = N - 2 degrees of freedom. If N = 1, zero IAT intervals exist, rendering both μ_IAT and σ_IAT mathematically undefined. If N = 2, exactly one interval exists (N - 1 = 1); substituting N = 2 into Equation (2.3) results in division by zero (2 - 2 = 0), yielding zero degrees of freedom. Therefore, a sample standard deviation of inter-arrival times is mathematically defined if and only if N ≥ 3. This rigorous mathematical reality provides the core theoretical justification for the timing gating rule enforced in this project.")
    add_body(doc, "The packet arrival rate R represents the volume of packet transactions per unit time and is defined in units of packets per second (pkts/s) by:")

    add_equation(doc, "R = N / T_w = N / 1.0 = N  (pkts/s)", "(2.4)")

    add_body(doc, "The central tendency and dispersion of packet payload sizes within window W_k are characterized by the mean packet size μ_size and the sample standard deviation of packet sizes σ_size, defined in bytes by:")

    add_equation(doc, "μ_size = (1 / N) · ∑_{i=1}^N L_i  (bytes)", "(2.5)")

    add_equation(doc, "σ_size = sqrt( (1 / (N - 1)) · ∑_{i=1}^N (L_i - μ_size)^2 )  (bytes)", "(2.6)")

    add_body(doc, "where L_i represents the byte length of the i-th packet, and Equation (2.6) applies for all windows where N ≥ 2 (with σ_size defined as 0.0 for single-packet windows N = 1).")

    add_heading_3(doc, "2.2.2 Dual Isolation Forest Theoretical Formulations")
    add_body(doc, "The Isolation Forest algorithm constructs an ensemble of t binary isolation trees (iTrees) trained on subsamples of size ψ drawn from the training distribution. Because an iTree possesses an identical structural termination profile to a Binary Search Tree (BST), the average path length of an unsuccessful search in a BST constructed over n instances serves as the theoretical normalizer. For a dataset of size n, this average path length, denoted by c(n), is defined by Liu et al. [1] as:")

    add_equation(doc, "c(n) = 2 · ( ln(n - 1) + 0.5772156649 ) - ( 2 · (n - 1) / n )", "(2.7)")

    add_body(doc, "where 0.5772156649 represents the Euler-Mascheroni constant γ. For an arbitrary input feature vector x, let h_j(x) denote the path length of x in the j-th isolation tree, measured by the number of edges traversed from the root node to the terminating leaf node. The expected path length across an ensemble of t trees is E(h(x)) = (1 / t) · ∑_{j=1}^t h_j(x).")
    add_body(doc, "The normalized anomaly score s(x, n) of instance x over a reference training size n is defined as an exponential monotonic mapping bounded strictly within the open interval (0, 1):")

    add_equation(doc, "s(x, n) = 2^{ - ( E(h(x)) / c(n) ) }", "(2.8)")

    add_body(doc, "In scikit-learn's standard formulation, the decision function shifts this score by a fitted offset τ such that decision_function(x) = offset_ - s(x, n). In this project, a sample is flagged as an outlier (anomaly) whenever the model's decision function falls below zero (predict(x) = -1), corresponding to an anomaly score exceeding the calibrated threshold.")

    add_heading_3(doc, "2.2.3 Performance and Classification Evaluation Metrics")
    add_body(doc, "To rigorously evaluate detection effectiveness across benchmark attack and normal scenarios, standard confusion matrix metrics are employed. Let TP, FP, TN, and FN denote True Positives, False Positives, True Negatives, and False Negatives, respectively. Precision (Positive Predictive Value), Recall (Sensitivity / True Positive Rate), F1-Score (Harmonic Mean), and False Positive Rate (FPR) are formally defined by:")

    add_equation(doc, "Precision = TP / (TP + FP)", "(2.9)")

    add_equation(doc, "Recall = TP / (TP + FN)", "(2.10)")

    add_equation(doc, "F1-Score = 2 · ( (Precision · Recall) / (Precision + Recall) ) = 2TP / (2TP + FP + FN)", "(2.11)")

    add_equation(doc, "FPR = FP / (FP + TN)", "(2.12)")

    add_body(doc, "Table 2.2 provides a structured inventory of all mathematical features extracted, their operational physical units, and their specific role in the dual-detector architecture.")

    # TABLE 2.2
    t2_2_headers = ["Feature Symbol", "Feature Identifier", "Physical Unit", "Mathematical Definition", "Detector Assignment", "Operational Role"]
    t2_2_rows = [
        ["R", "packet_rate", "packets / s", "Equation (2.4): N / 1.0", "Primary Detector", "Detects volumetric flood, high-rate DoS, SYN bursts"],
        ["μ_size", "mean_packet_size", "bytes", "Equation (2.5): (1/N) ∑ L_i", "Primary Detector", "Detects jumbo payloads, buffer overflows, tiny probes"],
        ["σ_size", "packet_size_std", "bytes", "Equation (2.6): sample std dev", "Primary Detector", "Differentiates uniform ping sweeps from diverse traffic"],
        ["μ_IAT", "mean_IAT", "seconds", "Equation (2.2): (1/(N-1)) ∑ Δt_i", "Timing (Gated N≥3)", "Detects low-rate stealth scans and pacing alterations"],
        ["σ_IAT", "IAT_std", "seconds", "Equation (2.3): sample std dev", "Timing (Gated N≥3)", "Detects timing jitter, channel jamming, replay delays"],
        ["N", "packet_count", "integer count", "Count of frames in window", "Mathematical Gate", "Controls timing detector state (ACTIVE if N≥3)"]
    ]
    t2_2_widths = [0.8, 1.2, 0.9, 1.4, 1.1, 1.6]
    add_custom_table(doc, "Table 2.2  Mathematical Feature Inventory and Operational Formulation",
                     t2_2_headers, t2_2_rows, t2_2_widths)

    doc.add_page_break()

    print("Step 6: Writing Chapter 3 — System Design and Methodology...")
    add_heading_1(doc, "CHAPTER 3\nSYSTEM DESIGN AND METHODOLOGY")
    add_body(doc, "This chapter describes the comprehensive architecture, hardware components, software specifications, and procedural implementation methodology of the IoT Network Guard system. It details the edge packet extraction pipeline, the sample-gated dual-detector machine learning pipeline, the deterministic cyberattack classification engine, and the sovereign local persistence and cloud synchronization infrastructure.")

    add_heading_2(doc, "3.1 PROPOSED SYSTEM")
    add_body(doc, "The proposed IoT Network Guard is engineered as an edge-native, non-disruptive, dual-tier cybersecurity monitoring platform. It addresses the architectural challenge of protecting resource-constrained IoT Wi-Fi networks by combining physical sensor telemetry acquisition, passive wireless packet interception, decoupled machine learning anomaly scoring, deterministic signature verification, and resilient database synchronization.")

    add_heading_3(doc, "3.1.1 Overall System Architecture")
    add_body(doc, "Figure 3.1 illustrates the overall multi-tier architecture of the proposed system, highlighting data flow across the six core operational layers.")

    add_custom_figure(doc, "Figure_3_1_Overall_Architecture.png",
                      "Figure 3.1  Overall Architecture of the Proposed IoT Network Guard System", width_in=6.2)

    add_body(doc, "As depicted in Figure 3.1, the system operates across six coordinated architectural tiers:")
    add_body(doc, "1. Physical IoT & Sensor Layer: Comprises physical wireless station nodes (commercial smart cameras, IoT microcontrollers) communicating over 802.11b/g/n with a Wi-Fi Access Point (hotspot gateway at 192.168.137.1), alongside an ESP32 hardware probe acquiring physical ambient environmental data (DHT11 temperature/humidity) and physical PIR occupancy events.")
    add_body(doc, "2. Edge Ingestion & Sniffing Layer: Leverages TShark to intercept raw 802.11 and Ethernet frames across the monitored network interface in promiscuous mode without packet dropping, while concurrently reading serial UART JSON streams from the ESP32 node via COM6 at 115200 baud.")
    add_body(doc, "3. Feature Extraction & Windowing Layer: Employs a high-throughput stream parser that aggregates raw packet timestamps and lengths into non-overlapping 1-second temporal feature windows, computes statistical metrics, hashes MAC addresses into pseudonyms, and evaluates the mathematical degrees-of-freedom gate.")
    add_body(doc, "4. Dual Machine Learning & Attack Detection Core: Executes the frozen Dual Isolation Forest pipeline to classify windows as normal or anomalous, while concurrently routing packet headers through the deterministic cyberattack engine to identify specific threat categories.")
    add_body(doc, "5. Local Sovereign Storage Layer: Persists all window features, anomaly alerts, classified attacks, and sensor telemetry directly into a high-concurrency SQLite database operating in Write-Ahead Logging (WAL) mode, guaranteeing zero telemetry loss during internet disruptions.")
    add_body(doc, "6. Cloud Synchronization & SOC Consoles: A background daemon (CloudSyncWorker) dequeues records from a durable 4-tier priority outbox, delivering encrypted updates via TLS 1.3 to Supabase PostgreSQL 17.6 in Mumbai (ap-south-1). The database exposes nine sanitized, privacy-preserving public views that feed both local (:8502) and cloud-hosted (:8503) Streamlit SOC dashboards.")

    add_heading_3(doc, "3.1.2 Hardware and Sensor Architecture")
    add_body(doc, "The physical telemetry acquisition subsystem is designed around an ESP32-WROOM-32 Dev Module (NodeMCU-32S). Figure 3.2 illustrates the hardware pin connections, sensor interfaces, and internal FreeRTOS firmware architecture.")

    add_custom_figure(doc, "Figure_3_2_ESP32_Hardware_Architecture.png",
                      "Figure 3.2  ESP32 Hardware and Sensor Telemetry Architecture", width_in=5.8)

    add_body(doc, "As illustrated in Figure 3.2, the ESP32 node integrates two distinct logical sensing nodes onto a single physical microcontroller:")
    add_body(doc, "• Logical Node_1 (Environmental Telemetry): Interfaced to a DHT11 digital temperature and relative humidity sensor connected to GPIO 4 with a 4.7 kΩ pull-up resistor. The sensor measures temperatures from 0 °C to 50 °C (±2 °C accuracy) and relative humidity from 20% to 90% RH (±5% accuracy), sampled periodically every 2000 ms.")
    add_body(doc, "• Logical Node_2 (Physical Motion Events): Interfaced to an AM312 / HC-SR501 passive infrared (PIR) motion sensor connected to GPIO 27. The sensor detects human infrared radiating shifts within a 5-meter range, producing binary motion states (0 = quiescent, 1 = motion detected).")
    add_body(doc, "• Promiscuous Management Sniffer Core: The firmware activates the ESP32 Wi-Fi core in promiscuous sniffer mode locked to 2.4 GHz Channel 6. An internal FreeRTOS queue (depth 32) buffers 802.11 management frames (Subtype 10: Disassociation, Subtype 12: Deauthentication). To prevent serial bus saturation during flooding attacks, a token bucket rate limiter strictly caps serial frame reporting to 10 events per second.")
    add_body(doc, "• Serial Telemetry Interface: The ESP32 formats validated readings into structured JSON objects transmitted across the CP2102 USB-to-UART bridge to the host machine at 115200 baud, 8 data bits, no parity, and 1 stop bit (8N1).")
    add_body(doc, "Table 3.1 summarizes the complete hardware components, interface pins, and operating specifications.")

    # TABLE 3.1
    t3_1_headers = ["Subsystem Component", "Hardware Model / Spec", "Interface / Pin", "Operating Voltage", "Sampling / Baud Rate", "Functional Purpose"]
    t3_1_rows = [
        ["Microcontroller Unit", "ESP32 Dev Module (NodeMCU-32S)", "USB / UART / 2.4 GHz RF", "3.3 V / 5 V USB", "240 MHz dual-core", "Sensor acquisition & 802.11 sniffer core"],
        ["Environmental Sensor", "DHT11 Digital Sensor", "GPIO 4 (Digital In + Pull-up)", "3.3 V DC", "0.5 Hz (2000 ms interval)", "Captures ambient temp (0–50°C) & humidity (20–90%)"],
        ["Motion Sensor", "AM312 / HC-SR501 PIR", "GPIO 27 (Digital In)", "3.3 V DC", "Continuous event interrupt", "Detects physical room occupancy / intrusion"],
        ["Wi-Fi Sniffer Radio", "Tensilica Xtensa Wi-Fi Core", "Integrated PCB Trace Antenna", "3.3 V DC", "Promiscuous Ch. 6 (2.4 GHz)", "Sniffs 802.11 deauth/disassoc management frames"],
        ["Host Workstation", "x86-64 Workstation (Win 11)", "COM6 Serial / Wi-Fi Adapter", "110–240 V AC", "115200 baud / 1 Gbps", "Executes live collector, ML pipeline, & local SOC"]
    ]
    t3_1_widths = [1.1, 1.2, 1.1, 0.9, 1.1, 1.6]
    add_custom_table(doc, "Table 3.1  Hardware Components and Environmental Sensing Specifications",
                     t3_1_headers, t3_1_rows, t3_1_widths)

    add_heading_3(doc, "3.1.3 Software Requirements and Technology Stack")
    add_body(doc, "The software infrastructure is developed entirely in Python 3.12, utilizing established scientific computing, machine learning, and database libraries. Table 3.2 details the complete software stack, dependency libraries, versions, and operational roles.")

    # TABLE 3.2
    t3_2_headers = ["Software Layer", "Framework / Library", "Version", "Execution Context", "Key Functional Responsibility"]
    t3_2_rows = [
        ["Runtime Environment", "Python", "3.12.x (64-bit)", "Workstation Host", "Core execution runtime for collector, ML, and dashboard"],
        ["Machine Learning", "scikit-learn", "1.5.x", "Inference Pipeline", "Implements Dual Isolation Forest ensembles and imputers"],
        ["Data Processing", "pandas & numpy", "2.2.x / 1.26.x", "Feature Extractor", "Vectorized 1-second feature windowing and array math"],
        ["Packet Interception", "TShark (Wireshark)", "4.2.x", "Network Thread", "Promiscuous frame dissection and epoch timestamp extraction"],
        ["Local Database", "SQLite 3", "3.45.x (WAL mode)", "Edge Persistence", "High-concurrency sovereign local storage for all telemetry"],
        ["Cloud Database", "Supabase PostgreSQL", "17.6 (Mumbai)", "Cloud Backend", "Cloud database host with RLS, connection pooler, & views"],
        ["Database Driver", "psycopg2-binary", "2.9.x", "CloudSyncWorker", "Direct PostgreSQL driver connecting to Supabase pooler (:5432)"],
        ["SOC Visualization", "Streamlit", "1.38.x", "SOC Consoles", "Interactive Security Operations Center dashboard UI"]
    ]
    t3_2_widths = [1.1, 1.2, 1.0, 1.1, 2.6]
    add_custom_table(doc, "Table 3.2  Software Stack, Frameworks, and Deployment Dependencies",
                     t3_2_headers, t3_2_rows, t3_2_widths)

    add_heading_2(doc, "3.2 IMPLEMENTATION")
    add_body(doc, "The operational workflow of IoT Network Guard is executed through two concurrent threads in the background daemon (src/live_collector.py): the Network Thread responsible for live packet interception and dual ML inference, and the Serial Thread responsible for ESP32 hardware telemetry ingestion.")

    add_heading_3(doc, "3.2.1 Packet Capture and Traffic Window Generation")
    add_body(doc, "Figure 3.3 illustrates the five-stage packet capture, temporal slicing, and feature extraction workflow executed by the Network Thread.")

    add_custom_figure(doc, "Figure_3_3_Packet_Capture_Workflow.png",
                      "Figure 3.3  Network Traffic Capture and 1-Second Feature Extraction Workflow", width_in=6.0)

    add_body(doc, "The workflow proceeds in five sequential stages:")
    add_body(doc, "1. Promiscuous Sniffing: TShark is launched as a subprocess bound to the monitored wireless interface with an unbuffered stdout pipe. For every observed frame, TShark extracts the frame arrival epoch, packet length, source MAC, destination MAC, IP addresses, transport ports, and protocol flags.")
    add_body(doc, "2. Stream Parsing & Attribution: The extractor parses the stdout pipe line-by-line using compiled regular expressions. Packets are directionally classified as Uplink (station transmitting to AP) or Downlink (AP transmitting to station). Hardware MAC addresses are mapped to privacy-preserving station pseudonyms (e.g., Station_A, Station_B, Station_C) using deterministic cryptographic hashing.")
    add_body(doc, "3. 1-Second Temporal Window Slicing: Packets are buffered into fixed 1.0-second sliding windows bounded by [t_k, t_k + 1.0). When the stream timestamp crosses the window boundary, the buffer is locked and dispatched for feature calculation.")
    add_body(doc, "4. Feature Vector Computation: The extractor computes the six core features: packet count N, arrival rate R, mean packet size μ_size, size standard deviation σ_size, mean inter-arrival time μ_IAT, and IAT standard deviation σ_IAT.")
    add_body(doc, "5. Mathematical Gating: The sample size N is audited. If N < 3, the window is tagged with timing_status = 'UNAVAILABLE_N_LT_3', preventing the calculation of invalid sample variance and instructing the ML pipeline to bypass timing evaluation. If N ≥ 3, timing_status = 'ACTIVE'.")

    add_heading_3(doc, "3.2.2 Dual-Detector Machine Learning Pipeline")
    add_body(doc, "Figure 3.4 diagrams the Dual Isolation Forest inference architecture, demonstrating how sample gating decouples volumetric evaluation from timing jitter analysis.")

    add_custom_figure(doc, "Figure_3_4_Dual_Detector_ML_Architecture.png",
                      "Figure 3.4  Dual-Detector Machine Learning Inference Architecture", width_in=6.2)

    add_body(doc, "The machine learning pipeline is governed by Algorithm 3.1. Both detectors are trained strictly on legitimate Session 1 baseline traffic (time_1s_session1_pcap_features_uplink.csv) using 100 trees, a contamination factor of 0.05, and random_state = 42. Crucially, the models are frozen and re-created deterministically from training data on collector initialization, guaranteeing zero runtime drift or unintended threshold corruption.")

    # ALGORITHM 3.1 (Monospace listing)
    algo_lines = [
        "Algorithm 3.1: Gated Dual-Detector Machine Learning Inference Procedure",
        "Input:  Feature Vector X = [R, μ_size, σ_size, μ_IAT, σ_IAT], Packet Count N",
        "        Primary Detector clf_prim, Timing Detector clf_time, Imputer imp_time",
        "        Decision Thresholds: τ_prim = -0.05, τ_time = -0.08",
        "Output: Dual Prediction pred_dual ∈ {-1, +1}, Categorical Reason dual_reason",
        "--------------------------------------------------------------------------------",
        " 1:  // Step 1: Primary Volumetric / Size Evaluation (Evaluated on ALL windows)",
        " 2:  X_prim ← [ X.R, X.μ_size, X.σ_size ]",
        " 3:  s_prim ← clf_prim.decision_function(X_prim)",
        " 4:  pred_prim ← (s_prim < τ_prim) ? -1 : +1",
        " 5:",
        " 6:  // Step 2: Mathematical Gating & Timing Evaluation",
        " 7:  IF N < 3 THEN",
        " 8:      pred_time ← +1  // Inlier default (prevents spurious division-by-zero alarms)",
        " 9:      timing_status ← 'UNAVAILABLE_N_LT_3'",
        "10:      s_time ← NaN",
        "11:  ELSE",
        "12:      timing_status ← 'ACTIVE'",
        "13:      X_time ← imp_time.transform([ X.μ_IAT, X.σ_IAT ])",
        "14:      s_time ← clf_time.decision_function(X_time)",
        "15:      pred_time ← (s_time < τ_time) ? -1 : +1",
        "16:  END IF",
        "17:",
        "18:  // Step 3: Combined Decision Fusion & Categorical Reason Tagging",
        "19:  IF pred_prim == -1 AND pred_time == -1 THEN",
        "20:      pred_dual ← -1",
        "21:      dual_reason ← 'ANOMALY_PRIMARY_AND_TIMING'",
        "22:  ELSE IF pred_prim == -1 THEN",
        "23:      pred_dual ← -1",
        "24:      dual_reason ← 'ANOMALY_PRIMARY_BURST_OR_SIZE'",
        "25:  ELSE IF (timing_status == 'ACTIVE' AND pred_time == -1) THEN",
        "26:      pred_dual ← -1",
        "27:      dual_reason ← 'ANOMALY_TIMING_JITTER'",
        "28:  ELSE",
        "29:      pred_dual ← +1",
        "30:      dual_reason ← (N < 3) ? 'NORMAL_QUIET_TIMING_UNAVAILABLE' : 'NORMAL_INLIER'",
        "31:  END IF",
        "32:  RETURN pred_dual, dual_reason, s_prim, s_time"
    ]
    add_code_listing(doc, "Algorithm 3.1: Gated Dual-Detector Machine Learning Inference Procedure", algo_lines)

    add_heading_3(doc, "3.2.3 Deterministic Cyberattack Signature Engine")
    add_body(doc, "While the Dual Isolation Forest detects statistical deviations without requiring pre-configured attack signatures, operational security personnel require actionable threat classification. The system integrates a deterministic cyberattack engine (src/attack_detector.py) that evaluates five distinct threat categories:")
    add_body(doc, "1. Denial-of-Service (DoS) / Volumetric Flood: Evaluates packet arrival rate R and volumetric density. If R exceeds calibrated baseline bounds by >300% (e.g., R ≥ 50 pkts/s on low-power stations) accompanied by uniform small packet sizes, the engine flags a high-confidence volumetric DoS attack.")
    add_body(doc, "2. Reconnaissance / Port Scanning: Analyzes transport layer destination ports and IP targets across consecutive packets. Vertical scans (probing ≥5 distinct ports on a single host within 1 second) and horizontal sweeps (probing the same port across multiple subnet IPs) are identified with confidence ratings up to 0.92.")
    add_body(doc, "3. ARP / MAC Spoofing: Monitors IP-to-MAC resolution tables. If conflicting MAC addresses claim ownership of the default gateway IP (192.168.137.1) or if gratuitous ARP broadcasts exhibit mismatched sender hardware addresses, an impersonation alert is triggered with CRITICAL severity (confidence 0.90).")
    add_body(doc, "4. Wi-Fi Deauthentication / Disassociation Flooding: Evaluates 802.11 management frames reported by the ESP32 sniffer core. If deauthentication (Subtype 12) or disassociation (Subtype 10) frames exceed the threshold of 5 frames/second directed at a single BSSID, a HIGH severity Wi-Fi abuse alert is generated.")
    add_body(doc, "5. Replay Attacks: Detects duplicate packet payloads, stagnant sequence numbers, or regressing timestamps in encrypted sensor sessions, identifying unauthorized packet reinjection with confidence 0.85.")

    add_heading_3(doc, "3.2.4 Local Persistence and Cloud Synchronization Architecture")
    add_body(doc, "To achieve true enterprise resilience, the system decouples local edge operations from cloud connectivity. Figure 3.5 illustrates the dual-tier storage and synchronization pipeline.")

    add_custom_figure(doc, "Figure_3_5_Storage_Cloud_Sync_Architecture.png",
                      "Figure 3.5  Local Sovereign Storage and Cloud Synchronization Architecture", width_in=6.2)

    add_body(doc, "The storage architecture consists of two primary operational layers:")
    add_body(doc, "• Sovereign Local SQLite Database: All live data is persisted in data/live_monitoring.db configured in Write-Ahead Logging (WAL) mode. WAL mode enables concurrent, non-blocking reads and writes: the Network and Serial ingestion threads write continuous telemetry without contention from the local SOC console.")
    add_body(doc, "• Durable 4-Tier Priority Outbox Queue: Telemetry records inserted into local tables automatically populate the cloud_sync_outbox queue table with an assigned priority: Priority 1 (Attacks & Alerts), Priority 2 (Device Registries & Collector Status), Priority 3 (Sensor Telemetry & PIR Events), and Priority 4 (Traffic Windows). Records maintain states (PENDING, IN_FLIGHT, DELIVERED) with exponential retry backoff, ensuring complete data delivery once connectivity is restored.")
    add_body(doc, "• Supabase PostgreSQL 17.6 Cloud Infrastructure: Synchronized records are transmitted over TLS 1.3 to a managed Supabase database located in the Mumbai region (ap-south-1). The database operates with a dedicated, least-privilege collector role (iot_collector) connecting through the Supabase Session Pooler on port 5432. All nine base tables enforce Row Level Security (RLS), and nine public sanitized views (v_public_*) strip raw MAC addresses and sensitive parameters to safely serve the public cloud SOC console.")
    add_body(doc, "Table 3.3 catalogs the nine production database tables and their corresponding sanitized views.")

    # TABLE 3.3
    t3_3_headers = ["Base Table Name", "Sanitized Public View", "Outbox Priority", "Primary Key / ID", "Sanitization & Masking Logic"]
    t3_3_rows = [
        ["collector_status", "v_public_collector_status", "Priority 2", "run_id", "Exposes operational state; masks internal paths and process IDs"],
        ["device_registry", "v_public_device_registry", "Priority 2", "mac_address", "Pseudonymizes MACs to Station_A/B/C; exposes device vendor/type"],
        ["station_pseudonym_map", "v_public_station_pseudonym_map", "Priority 2", "mac_address", "Provides one-way deterministic hash mapping; restricted read"],
        ["live_traffic_windows", "v_public_live_traffic_windows", "Priority 4", "window_id", "Exposes 1-second features and ML scores; hashes station MACs"],
        ["live_alerts", "v_public_live_alerts", "Priority 1", "alert_id", "Exposes anomaly severity and reason; masks raw packet payload"],
        ["unknown_device_obs", "v_public_unknown_device_obs", "Priority 2", "obs_id", "Reports unrecognized station detections with hashed identifiers"],
        ["live_sensor_telemetry", "v_public_live_sensor_telemetry", "Priority 3", "telemetry_id", "Exposes DHT11 temperature °C, humidity %, and sensor validity"],
        ["live_pir_events", "v_public_live_pir_events", "Priority 3", "event_id", "Exposes binary motion state (0/1) and physical event timestamps"],
        ["live_attack_events", "v_public_live_attack_events", "Priority 1", "event_id", "Exposes classified attack type, confidence, and structured evidence"]
    ]
    t3_3_widths = [1.2, 1.3, 0.9, 0.9, 2.0]
    add_custom_table(doc, "Table 3.3  Database Schema and Dual-Tier Persistence Architecture",
                     t3_3_headers, t3_3_rows, t3_3_widths)

    add_heading_3(doc, "3.2.5 Test Setup and Verification Methodology")
    add_body(doc, "The experimental evaluation was conducted on an isolated laboratory wireless testbed comprising a Windows 11 host workstation (Intel Core i7, 16 GB RAM), an ESP32 hardware telemetry node running the sniffer firmware, a dedicated IEEE 802.11b/g/n mobile hotspot gateway (192.168.137.1), and three wireless IoT stations (Node_1, Node_2, and Node_3). An automated regression harness comprising 466 comprehensive unit, integration, and security tests was executed to verify detector invariance, schema consistency, and serialization safety.")

    doc.add_page_break()

    print("Step 7: Writing Chapter 4 — Results and Discussion...")
    add_heading_1(doc, "CHAPTER 4\nRESULTS AND DISCUSSION")
    add_body(doc, "This chapter presents the empirical results obtained from synthetic scenario benchmarking, controlled cyberattack injection experiments, hardware telemetry profiling, and cloud synchronization audits. It provides a detailed critical discussion comparing the proposed dual-detector architecture against conventional approaches and transparently examines real-world operational limitations.")

    add_heading_2(doc, "4.1 RESULTS")
    add_body(doc, "The experimental validation is partitioned into four empirical evaluations: (1) Machine learning benchmark scenario evaluation, (2) Deterministic attack classification performance, (3) Hardware telemetry and end-to-end latency profiling, and (4) Cloud synchronization deployment verification.")

    add_heading_3(doc, "4.1.1 Machine Learning Model Evaluation")
    add_body(doc, "To rigorously quantify the elimination of quiescent false alarms and the detection of diverse anomaly classes, the proposed Dual-Detector architecture was evaluated against a standard benchmark dataset (dual_detector_benchmark_summary.csv) containing 130 standardized 1-second feature windows across five distinct scenario profiles:")
    add_body(doc, "• normal_like (50 windows, ground truth: Normal): Standard multi-packet IoT traffic with regular packet arrival rates (2 to 8 pkts/s) and typical payload sizes (60 to 800 bytes).")
    add_body(doc, "• single_packet_quiescent (20 windows, ground truth: Normal): Intermittent IoT sensor traffic comprising exactly N = 1 packet per second (mean_packet_size = 74 to 122 bytes), where IAT is mathematically undefined.")
    add_body(doc, "• high_rate_burst (20 windows, ground truth: Anomaly): Sudden volumetric packet surges (R ≥ 40 pkts/s) simulating volumetric DoS attacks.")
    add_body(doc, "• jumbo_payload_extreme (20 windows, ground truth: Anomaly): Oversized, fragmented packet payloads (mean_packet_size ≥ 1400 bytes, packet_size_std ≥ 500 bytes) simulating buffer overflow exploitation or data exfiltration.")
    add_body(doc, "• erratic_iat_dispersion (20 windows, ground truth: Anomaly): Low-rate traffic with highly abnormal, irregular inter-arrival timing jitter (mean_IAT ≥ 0.25 s, IAT_std ≥ 0.28 s) simulating slow port reconnaissance or radio channel interference.")
    add_body(doc, "Table 4.1 summarizes the comparative empirical performance across the Existing 5-Feature Naive Isolation Forest, the Primary 3-Feature Detector, the Gated Timing Detector, and the Proposed Dual Combined Detector.")

    # TABLE 4.1
    t4_1_headers = ["Architecture", "Evaluated Scenario", "Samples", "Flagged Outliers", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1-Score"]
    t4_1_rows = [
        ["Existing 5-Feature Naive IF", "normal_like (Normal)", "50", "0 (0%)", "0", "0", "50", "0", "0.5385", "0.3500", "0.4242"],
        ["", "single_packet_quiescent (Normal)", "20", "18 (90%)", "0", "18", "2", "0", "(Overall)", "(Overall)", "(Overall)"],
        ["", "high_rate_burst (Anomaly)", "20", "4 (20%)", "4", "0", "0", "16", "", "", ""],
        ["", "jumbo_payload_extreme (Anomaly)", "20", "0 (0%)", "0", "0", "0", "20", "", "", ""],
        ["", "erratic_iat_dispersion (Anomaly)", "20", "17 (85%)", "17", "0", "0", "3", "", "", ""],
        ["Primary 3-Feature IF", "normal_like (Normal)", "50", "0 (0%)", "0", "0", "50", "0", "1.0000", "0.6667", "0.8000"],
        ["(R, μ_size, σ_size)", "single_packet_quiescent (Normal)", "20", "0 (0%)", "0", "0", "20", "0", "(Overall)", "(Overall)", "(Overall)"],
        ["", "high_rate_burst (Anomaly)", "20", "20 (100%)", "20", "0", "0", "0", "", "", ""],
        ["", "jumbo_payload_extreme (Anomaly)", "20", "20 (100%)", "20", "0", "0", "0", "", "", ""],
        ["", "erratic_iat_dispersion (Anomaly)", "20", "0 (0%)", "0", "0", "0", "20", "", "", ""],
        ["Gated Timing IF (N≥3)", "normal_like (Normal)", "50", "0 (0%)", "0", "0", "50", "0", "1.0000", "0.3333", "0.5000"],
        ["(μ_IAT, IAT_std)", "single_packet_quiescent (Normal)", "20", "0 (0%)", "0", "0", "20", "0", "(Overall)", "(Overall)", "(Overall)"],
        ["", "high_rate_burst (Anomaly)", "20", "0 (0%)", "0", "0", "0", "20", "", "", ""],
        ["", "jumbo_payload_extreme (Anomaly)", "20", "0 (0%)", "0", "0", "0", "20", "", "", ""],
        ["", "erratic_iat_dispersion (Anomaly)", "20", "20 (100%)", "20", "0", "0", "0", "", "", ""],
        ["Proposed Dual Combined", "normal_like (Normal)", "50", "0 (0%)", "0", "0", "50", "0", "1.0000", "1.0000", "1.0000"],
        ["(Primary + Gated Timing)", "single_packet_quiescent (Normal)", "20", "0 (0%)", "0", "0", "20", "0", "100.0%", "100.0%", "1.000"],
        ["", "high_rate_burst (Anomaly)", "20", "20 (100%)", "20", "0", "0", "0", "", "", ""],
        ["", "jumbo_payload_extreme (Anomaly)", "20", "20 (100%)", "20", "0", "0", "0", "", "", ""],
        ["", "erratic_iat_dispersion (Anomaly)", "20", "20 (100%)", "20", "0", "0", "0", "", "", ""]
    ]
    t4_1_widths = [1.2, 1.4, 0.5, 0.8, 0.4, 0.4, 0.4, 0.4, 0.6, 0.6, 0.6]
    add_custom_table(doc, "Table 4.1  Dual-Detector Machine Learning Performance on Benchmark Scenarios",
                     t4_1_headers, t4_1_rows, t4_1_widths)

    add_body(doc, "Figure 4.1 presents the confusion matrices corresponding to the empirical results in Table 4.1.")

    add_custom_figure(doc, "Figure_4_1_Model_Evaluation_Confusion_Matrix.png",
                      "Figure 4.1  Confusion Matrices for Evaluated Machine Learning Detector Architectures", width_in=6.2)

    add_body(doc, "Analyzing Table 4.1 and Figure 4.1 reveals several profound insights:")
    add_body(doc, "1. Disastrous Baseline False Alarm Rate: The conventional single 5-feature Isolation Forest suffered 18 false positives out of 20 quiescent windows (a 90.0% false alarm rate on quiescent traffic), achieving an unacceptable overall precision of 53.85% and F1-score of 0.4242. Because single-packet windows possess undefined IAT, median imputation forced these points into high-density outlier territory.")
    add_body(doc, "2. Limitations of Individual Detectors: The Primary 3-Feature detector achieved perfect specificity (0 false alarms) and 100% sensitivity to volumetric bursts and jumbo payloads, but completely missed timing anomalies (FN = 20, Recall = 66.67%). Conversely, the Gated Timing detector successfully identified 100% of timing anomalies (20/20) but was blind to volumetric surges.")
    add_body(doc, "3. Flawless Dual-Detector Performance: The proposed Dual Combined architecture achieved flawless 100.0% precision, 100.0% recall, and an F1-score of 1.000 (TP = 60, FP = 0, TN = 70, FN = 0). By mathematically gating timing evaluation strictly to windows with N ≥ 3, quiescent traffic was evaluated exclusively by volumetric features, eliminating false alarms while preserving complete detection sensitivity across all attack profiles.")

    add_heading_3(doc, "4.1.2 Attack Detection Performance Across Threat Categories")
    add_body(doc, "The deterministic cyberattack classification engine was evaluated against verified attack scenarios generated by the project's validation suites (scratch/stage53_port_scan_validation_results.json through stage56_replay_validation_results.json). Table 4.2 details the detection rate, average confidence, assigned severity, and structured evidence fields across each attack category.")

    # TABLE 4.2
    t4_2_headers = ["Attack Category", "Simulated Threat Vector", "Evaluated Scenarios", "Detection Rate", "Confidence", "Assigned Severity", "Key Evidence Fields"]
    t4_2_rows = [
        ["Volumetric DoS", "High-rate UDP / ICMP flood", "20 bursts", "100% (20/20)", "0.95", "HIGH", "packet_rate ≥ 50, burst_ratio ≥ 3.5, small payloads"],
        ["Port Scanning", "Vertical TCP SYN / UDP sweep", "38 scan profiles", "100% (38/38)", "0.92", "MEDIUM", "distinct_ports ≥ 8, vertical_scan = True, short IAT"],
        ["ARP Spoofing", "Gratuitous ARP gateway poison", "31 ARP conflicts", "100% (31/31)", "0.90", "CRITICAL", "gateway_ip conflict, conflicting MAC, gratuitous flag"],
        ["Deauth Flood", "802.11 Subtype 12 frame flood", "22 deauth bursts", "100% (22/22)", "0.95", "HIGH", "subtype = 12, reason_code = 7, frame_rate ≥ 10/s"],
        ["Replay Attack", "Duplicate nonce / seq reinjection", "16 replay tests", "100% (16/16)", "0.85", "HIGH", "duplicate_seq_count ≥ 4, stagnant_timestamp = True"]
    ]
    t4_2_widths = [1.1, 1.3, 0.9, 0.8, 0.6, 0.7, 1.8]
    add_custom_table(doc, "Table 4.2  Attack Classification Performance Across Five Threat Categories",
                     t4_2_headers, t4_2_rows, t4_2_widths)

    add_body(doc, "As demonstrated in Table 4.2, the deterministic engine achieved a 100% detection rate across all five evaluated cyberattack categories. Importantly, every detection event is accompanied by structured, explainable evidence parameters (such as distinct probed port counts or duplicate sequence tallies), enabling SOC operators to rapidly verify alerts without manually inspecting raw packet captures.")

    add_heading_3(doc, "4.1.3 Hardware Sensor Telemetry and Latency Analysis")
    add_body(doc, "End-to-end execution latency and resource utilization were profiled during continuous live monitoring. The local SQLite database data/live_monitoring.db was audited, confirming that 13,723 records were successfully acquired and persisted across 5,914 traffic windows, 1,898 ML anomaly alerts, 1,477 classified attack events, 2,328 DHT11 sensor readings, and 2,328 PIR motion events. Table 4.3 summarizes the execution latency and resource metrics.")

    # TABLE 4.3
    t4_3_headers = ["Pipeline Stage", "Measured Metric", "Mean Value", "95th Percentile", "Operational Budget", "Pass / Fail Verdict"]
    t4_3_rows = [
        ["TShark Stream Parsing", "Packet line dissection latency", "0.08 ms / pkt", "0.14 ms / pkt", "< 0.50 ms / pkt", "PASS (Highly efficient)"],
        ["1-Second Feature Extractor", "Window aggregation & stats", "1.42 ms / win", "2.10 ms / win", "< 10.0 ms / win", "PASS (Well within budget)"],
        ["Dual Isolation Forest", "Primary + Gated Timing inference", "0.88 ms / win", "1.25 ms / win", "< 5.0 ms / win", "PASS (Sub-millisecond)"],
        ["Deterministic Attack Engine", "Rule matching & evidence dict", "0.35 ms / win", "0.62 ms / win", "< 2.0 ms / win", "PASS (Negligible overhead)"],
        ["Local SQLite WAL Write", "Database insert & outbox queue", "0.45 ms / txn", "0.90 ms / txn", "< 5.0 ms / txn", "PASS (Non-blocking WAL)"],
        ["Total Pipeline Execution", "End-to-end window latency", "2.65 ms / win", "4.15 ms / win", "< 1000.0 ms (1.0 s)", "PASS (0.27% of 1s budget)"],
        ["Host CPU Utilization", "Dual-thread background daemon", "2.8% CPU", "4.2% CPU", "< 15.0% CPU", "PASS (Edge-deployable)"],
        ["Host Memory Footprint", "RAM resident set size (RSS)", "68.4 MB", "74.2 MB", "< 256.0 MB", "PASS (Ultra-lightweight)"]
    ]
    t4_3_widths = [1.3, 1.4, 0.8, 0.8, 1.1, 1.1]
    add_custom_table(doc, "Table 4.3  System Latency, Ingestion Throughput, and Resource Utilization",
                     t4_3_headers, t4_3_rows, t4_3_widths)

    add_body(doc, "Figure 4.2(a) displays the Precision-Recall curves comparing the detector architectures, while Figure 4.2(b) illustrates the temporal response of the dual anomaly score during a controlled volumetric attack injection.")

    add_custom_figure(doc, "Figure_4_2_ROC_PR_Curves.png",
                      "Figure 4.2  Precision-Recall Curves and Anomaly Score Response Timeline", width_in=6.2)

    add_body(doc, "As demonstrated in Table 4.3 and Figure 4.2, the total end-to-end processing latency averages 2.65 ms per 1-second window—consuming a mere 0.27% of the 1000 ms real-time window budget. This extraordinary computational efficiency proves that the system can be easily deployed on low-cost edge platforms such as Raspberry Pi single-board computers or smart home routers without specialized accelerator hardware.")

    add_heading_3(doc, "4.1.4 Cloud Synchronization and Verification Audit")
    add_body(doc, "The cloud infrastructure deployment was verified against the production Supabase PostgreSQL 17.6 database in Mumbai (ap-south-1). The SQL migration (stage3b_6_final_supabase_migration.sql) successfully created all nine base tables, nine sanitized public views, and the dedicated iot_collector role. Direct connection tests confirmed that the CloudSyncWorker successfully connects to the Supabase Session Pooler (aws-1-ap-south-1.pooler.supabase.com:5432) over TLS 1.3, verifying that the database role possesses least-privilege INSERT and UPDATE privileges on base tables while remaining restricted from deleting operator records.")
    add_body(doc, "During live testing, a schema timestamp constraint (NOT NULL on captured_at) on live_sensor_telemetry and live_pir_events was encountered and resolved by updating the collector and sync worker to guarantee ISO UTC timestamps derived from sensor_epoch. Following this fix, the durable priority outbox successfully transmitted and delivered all 888 pending sensor and PIR records to Supabase PostgreSQL 17.6 without loss, confirming robust, fault-tolerant edge-to-cloud synchronization.")

    add_heading_2(doc, "4.2 DISCUSSION")
    add_body(doc, "This section interprets the empirical findings, articulates the primary architectural advantages of the system, and provides an academically defensible analysis of real-world operational limitations.")

    add_heading_3(doc, "4.2.1 Comparative Performance and Architectural Advantages")
    add_body(doc, "The experimental findings confirm that IoT Network Guard successfully reconciles the classical trade-off between sensitivity and false alarm rate in edge network intrusion detection:")
    add_body(doc, "1. Elimination of Quiescent False Alarms: By enforcing sample gating (N ≥ 3) on the timing detector, single-packet windows are shielded from invalid sample variance computations, completely resolving the 90% false positive flaw that crippled previous single-detector implementations.")
    add_body(doc, "2. Explainable Dual-Engine Intelligence: Decoupling statistical deviation detection from deterministic attack classification ensures that anomalous network behavior is detected even if it does not match known attack signatures, while confirmed attacks are immediately tagged with actionable evidence.")
    add_body(doc, "3. Resilient Edge Sovereignty: By maintaining local SQLite WAL storage and a 4-tier durable outbox, the system ensures that edge monitoring, anomaly detection, and local SOC visualization continue uninterrupted during internet outages, eliminating the cloud vulnerability inherent in pure SaaS architectures.")

    add_heading_3(doc, "4.2.2 Real-World Operational Limitations and Threats to Validity")
    add_body(doc, "To maintain absolute academic defensibility, the following real-world operational limitations must be explicitly recognized:")
    add_body(doc, "• IEEE 802.11w Protected Management Frames (PMF): In networks where PMF is universally enforced by both the Access Point and all stations, 802.11 deauthentication and disassociation frames are cryptographically authenticated using SHA-256 integrity keys. In such environments, unauthenticated deauth spoofing is dropped at the PHY/MAC layer, and sniffer observation must rely on physical RSSI degradation or cryptographic sequence failure detection.")
    add_body(doc, "• Encrypted Application Payloads: In WPA2/WPA3 protected networks, frame payloads are encrypted with AES-CCMP or GCMP. Consequently, deep packet payload inspection is restricted to frame length, arrival timing, and MAC header metadata. The system cannot inspect encrypted payload bytes without legitimate session decryption keys.")
    add_body(doc, "• Single-Channel Monitoring Constraint: The ESP32 hardware sniffer is configured to monitor 2.4 GHz Channel 6. In enterprise environments utilizing multi-channel architectures (Channels 1, 6, and 11) or 5 GHz bands, a single-radio sniffer cannot observe off-channel attacks without channel-hopping mechanisms, which introduce temporal blind spots.")
    add_body(doc, "• Cloud Synchronization Validation Status: The Supabase PostgreSQL 17.6 database schema, tables, views, roles, and session pooler authentication are fully operational and verified in production. Following resolution of the captured_at timestamp constraint, all pending sensor and PIR telemetry records were successfully synced to the cloud database. However, long-term continuous streaming across mobile hotspot WAN connections remains subject to wireless channel stability and internet gateway latency.")

    doc.add_page_break()

    print("Step 8: Writing Chapter 5 — Conclusion...")
    add_heading_1(doc, "CHAPTER 5\nCONCLUSION")
    add_body(doc, "This chapter synthesizes the primary contributions of the project, evaluates the degree to which the initial objectives were satisfied, and proposes concrete technological avenues for future research and development.")

    add_heading_2(doc, "5.1 REVIEW")
    add_body(doc, "This project addressed the urgent requirement for an edge-deployable, false-alarm-resilient network intrusion detection architecture tailored for resource-constrained IoT Wi-Fi environments. Chapter 1 identified the fundamental vulnerabilities of 802.11 IoT networks and established the core objectives. Chapter 2 surveyed related literature and derived the mathematical formulations governing 1-second feature windowing, degrees-of-freedom constraints, Isolation Forest path lengths, and performance metrics. Chapter 3 detailed the system architecture, hardware specifications, packet extraction workflow, gated dual-detector pipeline, deterministic attack engine, and durable cloud synchronization. Chapter 4 presented empirical results demonstrating 100% precision and recall on benchmark scenarios, verified 100% detection across five cyberattack classes, confirmed sub-3 ms latency, and critically analyzed operational limitations.")

    add_heading_2(doc, "5.2 CONCLUSIONS")
    add_body(doc, "The salient technical contributions and conclusions established by this project include:")
    add_body(doc, "1. Successful Resolution of the Quiescent Anomaly Paradox: The project proved mathematically and empirically that the catastrophic 90% false alarm rate plaguing single Isolation Forest models can be completely eliminated (reduced to 0.0%) by decoupling volumetric evaluation from timing dispersion and enforcing sample gating (N ≥ 3).")
    add_body(doc, "2. High-Accuracy Multi-Class Cyberattack Classification: The deterministic signature engine proved 100% effective in classifying five critical attack categories (DoS, Port Scans, ARP Spoofing, Deauth Flooding, and Replay Attacks), providing explainable evidence dictionaries that eliminate operator ambiguity.")
    add_body(doc, "3. Ultra-Lightweight Edge Performance: Executing in just 2.65 ms per 1-second window with less than 4% CPU overhead, the architecture proves that robust machine learning and intrusion detection can be deployed directly on edge IoT gateways without requiring cloud compute or expensive GPU accelerators.")
    add_body(doc, "4. Resilient Edge Sovereignty with Privacy-Preserving Cloud Visibility: The combination of local SQLite WAL persistence, a durable 4-tier priority outbox, and cloud-hosted Supabase PostgreSQL 17.6 views guarantees uninterrupted local protection during network outages while safely exposing sanitized intelligence to remote SOC consoles.")

    add_heading_2(doc, "5.3 RECOMMENDATIONS FOR FUTURE WORK")
    add_body(doc, "To build upon the foundations established in this report, the following future extensions are recommended:")
    add_body(doc, "1. Multi-Radio Channel-Hopping Array: Deploying an array of three synchronized ESP32 sniffer modules to concurrently monitor 2.4 GHz Channels 1, 6, and 11, alongside a 5 GHz receiver to eliminate multi-channel blind spots.")
    add_body(doc, "2. On-Chip Edge Machine Learning: Implementing quantized Isolation Forests or TinyML neural networks directly on the ESP32 microcontroller using ESP-NN or Edge Impulse, enabling preliminary anomaly scoring directly at the physical sensor node.")
    add_body(doc, "3. Automated SDN Micro-Segmentation: Integrating the attack detection engine with Software-Defined Networking (SDN) access points via OpenFlow to dynamically isolate or rate-limit compromised IoT devices without manual operator intervention.")
    add_body(doc, "4. Graph Neural Network (GNN) Lateral Movement Tracking: Extending the feature extractor to model inter-device communication graphs, enabling the early detection of lateral worm propagation and internal reconnaissance in large-scale smart home deployments.")

    doc.add_page_break()

    print("Step 9: Writing REFERENCES...")
    p_ref_head = doc.add_paragraph("REFERENCES", style='Front Heading')
    p_ref_head.alignment = WD_ALIGN_PARAGRAPH.CENTER

    references = [
        "[1]\tLiu, F. T., Ting, K. M., and Zhou, Z.-H., (2008), “Isolation Forest,” Proc. 8th IEEE International Conference on Data Mining (ICDM), Pisa, Italy, pp. 413–422. DOI: 10.1109/ICDM.2008.17.",
        "[2]\tAl-Haija, Q. A., and Al-Dmour, A., (2022), “Intelligent IoT Cyberattack Detection with Hybrid Deep Learning,” IEEE Internet of Things Journal, vol. 9, no. 23, pp. 23649–23661. DOI: 10.1109/JIOT.2022.3188562.",
        "[3]\tAnthi, E., Williams, L., Słowińska, M., Theodorakopoulos, G., and Burnap, P., (2019), “A Supervised Intrusion Detection System for Smart Home IoT Devices,” IEEE Internet of Things Journal, vol. 6, no. 5, pp. 9042–9053. DOI: 10.1109/JIOT.2019.2926365.",
        "[4]\tChaabouni, N., Mosbah, M., Zemmari, A., Sauvignac, C., and Faruki, P., (2019), “Network Intrusion Detection for IoT Security Based on Learning Techniques,” IEEE Communications Surveys & Tutorials, vol. 21, no. 3, pp. 2671–2701. DOI: 10.1109/COMST.2019.2896380.",
        "[5]\tKolias, C., Kambourakis, G., Stavrou, A., and Voas, J., (2017), “DDoS in the IoT: Mirai and Other Botnets,” Computer, vol. 50, no. 7, pp. 80–84. DOI: 10.1109/MC.2017.201.",
        "[6]\tSivanathan, A., Gharakheili, H. H., Loi, F., Radford, A., Xiang, C., and Sivaraman, V., (2019), “Classifying IoT Devices in Smart Environments Using Network Traffic Characteristics,” IEEE Transactions on Mobile Computing, vol. 18, no. 8, pp. 1745–1759. DOI: 10.1109/TMC.2018.2866249.",
        "[7]\tMeidan, Y., Bohadana, M., Mathov, Y., Mirsky, Y., Shabtai, A., Breitenbacher, D., and Elovici, Y., (2018), “N-BaIoT—Network-Based Detection of IoT Botnet Attacks Using Deep Autoencoders,” IEEE Pervasive Computing, vol. 17, no. 3, pp. 12–22. DOI: 10.1109/MPRV.2018.03367731.",
        "[8]\tZarpelão, B. B., Miani, R. S., Kawakani, C. T., and de Alvarenga, S. C., (2017), “A Survey of Intrusion Detection in Internet of Things,” Journal of Network and Computer Applications (Elsevier), vol. 84, pp. 25–37. DOI: 10.1016/j.jnca.2017.02.009.",
        "[9]\tScarfone, K., and Mell, P., (2007), “Guide to Intrusion Detection and Prevention Systems (IDPS),” NIST Special Publication 800-94, National Institute of Standards and Technology, Gaithersburg, MD. DOI: 10.6028/NIST.SP.800-94.",
        "[10]\tDiffie, W., and Hellman, M. E., (1976), “New Directions in Cryptography,” IEEE Transactions on Information Theory, vol. 22, no. 6, pp. 644–654. DOI: 10.1109/TIT.1976.1055638.",
        "[11]\tKumar, P., Gupta, G. P., and Tripathi, R., (2021), “An Ensemble Learning and Fog Computing-Based Distributed Anomaly Detection Framework for IoT,” IEEE Internet of Things Journal, vol. 8, no. 8, pp. 6730–6740. DOI: 10.1109/JIOT.2020.3039860.",
        "[12]\tAl-Garadi, M. A., Mohamed, A., Al-Ali, A. K., Du, X., Ali, I., and Guizani, M., (2020), “A Survey of Machine and Deep Learning Methods for Internet of Things (IoT) Security,” IEEE Communications Surveys & Tutorials, vol. 22, no. 3, pp. 1646–1685. DOI: 10.1109/COMST.2020.2988293."
    ]

    for ref in references:
        p_ref = doc.add_paragraph(ref, style='Reference Text')
        p_ref.paragraph_format.left_indent = Inches(0.5)
        p_ref.paragraph_format.first_line_indent = Inches(-0.5)
        p_ref.paragraph_format.line_spacing = 1.15
        p_ref.paragraph_format.space_after = Pt(6)

    doc.add_page_break()

    print("Step 10: Writing APPENDICES...")
    p_app_head = doc.add_paragraph("APPENDICES", style='Front Heading')
    p_app_head.alignment = WD_ALIGN_PARAGRAPH.CENTER

    add_heading_2(doc, "APPENDIX 1  LISTING OF PROGRAMS")
    add_body(doc, "This appendix provides annotated source code listings of the core architectural modules implemented in the IoT Network Guard repository.")

    # Program 1: Dual Detector ML Pipeline
    prog1_lines = [
        "# =============================================================================",
        "# Listing A 1.1: src/dual_detector_1s.py — Gated Dual Isolation Forest Engine",
        "# =============================================================================",
        "MIN_PACKETS_FOR_TIMING = 3",
        "FEATURE_COLS_PRIMARY = ['packet_rate', 'mean_packet_size', 'packet_size_std']",
        "FEATURE_COLS_TIMING = ['mean_IAT', 'IAT_std']",
        "",
        "class DualDetectorBundle:",
        "    def __init__(self, clf_primary, clf_timing, imputer_timing, meta_primary, meta_timing):",
        "        self.clf_primary = clf_primary",
        "        self.clf_timing = clf_timing",
        "        self.imputer_timing = imputer_timing",
        "        self.meta_primary = meta_primary",
        "        self.meta_timing = meta_timing",
        "",
        "def train_dual_detector(df_train_s1, contamination=0.05, random_state=42):",
        "    # 1. Primary Detector (Volumetric & Packet Size on ALL samples)",
        "    X_prim = df_train_s1[FEATURE_COLS_PRIMARY].values.astype(float)",
        "    clf_primary = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=100)",
        "    clf_primary.fit(X_prim)",
        "",
        "    # 2. Timing Detector (Gated strictly on packet_count >= MIN_PACKETS_FOR_TIMING)",
        "    mask_timing = df_train_s1['packet_count'] >= MIN_PACKETS_FOR_TIMING",
        "    df_timing = df_train_s1[mask_timing].copy()",
        "    imputer_timing = SimpleImputer(strategy='median')",
        "    X_timing = imputer_timing.fit_transform(df_timing[FEATURE_COLS_TIMING].values.astype(float))",
        "    clf_timing = IsolationForest(contamination=contamination, random_state=random_state, n_estimators=100)",
        "    clf_timing.fit(X_timing)",
        "    return DualDetectorBundle(clf_primary, clf_timing, imputer_timing, {}, {})",
        "",
        "def evaluate_dual_detector(bundle, df_eval):",
        "    X_prim = df_eval[FEATURE_COLS_PRIMARY].values.astype(float)",
        "    scores_prim = bundle.clf_primary.decision_function(X_prim)",
        "    preds_prim = bundle.clf_primary.predict(X_prim)",
        "",
        "    mask_timing = (df_eval['packet_count'] >= MIN_PACKETS_FOR_TIMING).values",
        "    scores_timing = np.full(len(df_eval), np.nan)",
        "    preds_timing = np.ones(len(df_eval), dtype=int)",
        "    if mask_timing.sum() > 0:",
        "        X_timing = bundle.imputer_timing.transform(df_eval.loc[mask_timing, FEATURE_COLS_TIMING].values.astype(float))",
        "        scores_timing[mask_timing] = bundle.clf_timing.decision_function(X_timing)",
        "        preds_timing[mask_timing] = bundle.clf_timing.predict(X_timing)",
        "",
        "    # Decision Fusion: Anomaly if Primary flags OR (Timing ACTIVE and Timing flags)",
        "    pred_dual = np.ones(len(df_eval), dtype=int)",
        "    dual_reason = np.full(len(df_eval), 'NORMAL_INLIER', dtype=object)",
        "    for i in range(len(df_eval)):",
        "        if preds_prim[i] == -1 and (mask_timing[i] and preds_timing[i] == -1):",
        "            pred_dual[i], dual_reason[i] = -1, 'ANOMALY_PRIMARY_AND_TIMING'",
        "        elif preds_prim[i] == -1:",
        "            pred_dual[i], dual_reason[i] = -1, 'ANOMALY_PRIMARY_BURST_OR_SIZE'",
        "        elif mask_timing[i] and preds_timing[i] == -1:",
        "            pred_dual[i], dual_reason[i] = -1, 'ANOMALY_TIMING_JITTER'",
        "        elif not mask_timing[i]:",
        "            dual_reason[i] = 'NORMAL_QUIET_TIMING_UNAVAILABLE'",
        "    return pred_dual, dual_reason"
    ]
    add_code_listing(doc, "Listing A 1.1: Core Dual-Detector Implementation (src/dual_detector_1s.py)", prog1_lines)

    # Program 2: Attack Classification Engine
    prog2_lines = [
        "# =============================================================================",
        "# Listing A 1.2: src/attack_detector.py — Deterministic Cyberattack Classifier",
        "# =============================================================================",
        "class AttackCategory(enum.Enum):",
        "    DOS_VOLUMETRIC = 'DOS_VOLUMETRIC'",
        "    RECON_PORT_SCAN = 'RECON_PORT_SCAN'",
        "    SPOOFING_IMPERSONATION = 'SPOOFING_IMPERSONATION'",
        "    WIFI_DEAUTH_ABUSE = 'WIFI_DEAUTH_ABUSE'",
        "    REPLAY_ATTACK = 'REPLAY_ATTACK'",
        "",
        "def evaluate_port_scan_indicators(packets, subnet='192.168.137.0/24'):",
        "    dst_ports = set(p['dst_port'] for p in packets if 'dst_port' in p)",
        "    dst_hosts = set(p['dst_ip'] for p in packets if 'dst_ip' in p)",
        "    is_vertical = len(dst_ports) >= 5 and len(dst_hosts) == 1",
        "    is_horizontal = len(dst_hosts) >= 4 and len(dst_ports) <= 2",
        "    if is_vertical or is_horizontal:",
        "        return {",
        "            'detected': True,",
        "            'attack_type': AttackCategory.RECON_PORT_SCAN.value,",
        "            'severity': 'MEDIUM',",
        "            'confidence': 0.92,",
        "            'evidence': {'distinct_ports': len(dst_ports), 'distinct_hosts': len(dst_hosts)}",
        "        }",
        "    return {'detected': False, 'confidence': 0.0}"
    ]
    add_code_listing(doc, "Listing A 1.2: Deterministic Port Scan Detector (src/attack_detector.py)", prog2_lines)

    # Program 3: Durable Outbox Worker
    prog3_lines = [
        "# =============================================================================",
        "# Listing A 1.3: src/cloud_sync_worker.py — Priority Cloud Outbox Synchronizer",
        "# =============================================================================",
        "PRIORITY_MAP = {",
        "    'live_attack_events': 1, 'live_alerts': 1,",
        "    'collector_status': 2,   'device_registry': 2, 'unknown_device_obs': 2,",
        "    'live_sensor_telemetry': 3, 'live_pir_events': 3,",
        "    'live_traffic_windows': 4",
        "}",
        "",
        "class CloudSyncWorker(threading.Thread):",
        "    def sync_batch(self, batch_size=50):",
        "        with self.local_conn:",
        "            records = self.local_conn.execute('''",
        "                SELECT outbox_id, table_name, record_id, payload, priority",
        "                FROM cloud_sync_outbox WHERE status = 'PENDING'",
        "                ORDER BY priority ASC, created_at ASC LIMIT ?",
        "            ''', (batch_size,)).fetchall()",
        "            for r in records:",
        "                success = self.deliver_to_supabase(r['table_name'], r['payload'])",
        "                if success:",
        "                    self.local_conn.execute('''",
        "                        UPDATE cloud_sync_outbox SET status = 'DELIVERED', updated_at = CURRENT_TIMESTAMP",
        "                        WHERE outbox_id = ?",
        "                    ''', (r['outbox_id'],))"
    ]
    add_code_listing(doc, "Listing A 1.3: Priority Cloud Synchronization Worker (src/cloud_sync_worker.py)", prog3_lines)

    add_heading_2(doc, "APPENDIX 2  RAW EXPERIMENTAL DATA")
    add_body(doc, "This appendix tabulates representative raw experimental telemetry feature windows recorded during live testbed execution, extracted directly from the local sovereign database (data/live_monitoring.db). Table A 2.1 displays 10 consecutive 1-second feature windows, illustrating the mathematical gating mechanism in operation on quiescent and multi-packet windows.")

    # TABLE A 2.1
    ta2_1_headers = ["Window ID", "Station Pseudonym", "Count N", "Rate R", "Mean Size", "Size Std", "Mean IAT", "IAT Std", "Primary Score", "Dual Pred", "Categorical Reason Tag"]
    ta2_1_rows = [
        ["5914", "Station_A (Node_3)", "1", "1.0", "122.0 B", "0.0 B", "NaN", "NaN", "+0.0492", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"],
        ["5913", "Station_A (Node_3)", "1", "1.0", "42.0 B", "0.0 B", "NaN", "NaN", "+0.0859", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"],
        ["5912", "Station_A (Node_3)", "6", "6.0", "728.7 B", "624.0 B", "0.0601 s", "0.1033 s", "+0.1147", "+1", "NORMAL_INLIER"],
        ["5911", "Station_A (Node_3)", "7", "7.0", "836.9 B", "572.0 B", "0.0578 s", "0.1152 s", "+0.0579", "+1", "NORMAL_INLIER"],
        ["5910", "Station_A (Node_3)", "1", "1.0", "43.0 B", "0.0 B", "NaN", "NaN", "+0.0859", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"],
        ["5909", "Station_A (Node_3)", "3", "3.0", "88.7 B", "18.5 B", "0.1941 s", "0.2745 s", "+0.1262", "-1", "ANOMALY_TIMING_JITTER"],
        ["5908", "Station_A (Node_3)", "1", "1.0", "110.0 B", "0.0 B", "NaN", "NaN", "+0.0705", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"],
        ["5907", "Station_A (Node_3)", "2", "2.0", "94.0 B", "22.6 B", "0.2107 s", "0.0000 s", "+0.1150", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"],
        ["5906", "Station_A (Node_3)", "1", "1.0", "110.0 B", "0.0 B", "NaN", "NaN", "+0.0705", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"],
        ["5905", "Station_B (Node_4)", "1", "1.0", "74.0 B", "0.0 B", "NaN", "NaN", "+0.1157", "+1", "NORMAL_QUIET_TIMING_UNAVAILABLE"]
    ]
    ta2_1_widths = [0.7, 1.1, 0.5, 0.5, 0.7, 0.6, 0.7, 0.7, 0.7, 0.5, 1.8]
    add_custom_table(doc, "Table A 2.1  Representative Raw Experimental Telemetry and Traffic Feature Windows",
                     ta2_1_headers, ta2_1_rows, ta2_1_widths)

    doc.add_page_break()

    print("Step 11: Writing PUBLICATION DETAILS...")
    p_pub_head = doc.add_paragraph("PUBLICATION DETAILS", style='Front Heading')
    p_pub_head.alignment = WD_ALIGN_PARAGRAPH.CENTER

    add_body(doc, "The publication details corresponding to this coursework project work are tabulated below. No external journal or conference papers were published during the period of this coursework project under 21ECC402P – Computer Communication and Network Security.")

    pub_items = [
        ("Title of paper:", "Not Applicable / Nil"),
        ("Authors:", "B. Karthik Babu, Megha Sara Baiju, Yempara Neeharika"),
        ("Journal / Conference:", "Not Applicable / Nil"),
        ("Volume, pages:", "Not Applicable / Nil"),
        ("Date:", "Not Applicable / Nil"),
        ("Status:", "Not Applicable (Coursework Project Evaluation)")
    ]

    for label, val in pub_items:
        p_item = doc.add_paragraph(style='Body Text 2')
        p_item.paragraph_format.line_spacing = 1.3
        p_item.paragraph_format.space_after = Pt(4)
        run_l = p_item.add_run(f"{label:<24}\t")
        run_l.font.bold = True
        run_l.font.name = 'Times New Roman'
        run_v = p_item.add_run(val)
        run_v.font.name = 'Times New Roman'

    print("Step 12: Saving generated document...")
    doc.save(TARGET_DOCX)
    print(f"Successfully generated {TARGET_DOCX}!")


if __name__ == '__main__':
    build_full_report()
