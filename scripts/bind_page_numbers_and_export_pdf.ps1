# PowerShell Script: Bind Exact Page Numbers to TOC, LOT, LOF and Export PDF
# File: scripts/bind_page_numbers_and_export_pdf.ps1

$ErrorActionPreference = "Stop"

$docxPath = (Resolve-Path "IoT_Network_Guard_Final_Project_Report.docx").Path
$pdfPath = [System.IO.Path]::ChangeExtension($docxPath, ".pdf")

Write-Host "Starting Microsoft Word COM Automation..."
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = [Microsoft.Office.Interop.Word.WdAlertLevel]::wdAlertsNone

try {
    Write-Host "Opening document: $docxPath"
    $doc = $word.Documents.Open($docxPath)
    
    Write-Host "Forcing document repagination..."
    $doc.Repaginate()
    
    # 1. First pass: Find actual page numbers for all headings, tables, and figures
    Write-Host "Scanning paragraphs for headings, tables, and figures..."
    $pageMap = @{}
    
    for ($idx = 1; $idx -le $doc.Paragraphs.Count; $idx++) {
        $p = $doc.Paragraphs.Item($idx)
        # Skip paragraphs inside tables to avoid matching Table of Contents entries
        if ($p.Range.Tables.Count -gt 0) { continue }

        $text = $p.Range.Text.Trim()
        if ($text.Length -eq 0) { continue }
        
        $adjPage = $p.Range.Information(1)  # wdActiveEndAdjustedPageNumber
        $physPage = $p.Range.Information(3) # wdActiveEndPageNumber
        
        # Match headings
        if ($text -cmatch "^CHAPTER 1\s+INTRODUCTION") { $pageMap["1 INTRODUCTION"] = "$adjPage" }
        elseif ($text -match "^1\.1 PROBLEM STATEMENT") { $pageMap["1.1 PROBLEM STATEMENT"] = "$adjPage" }
        elseif ($text -match "^1\.1\.1 Background") { $pageMap["1.1.1 Background"] = "$adjPage" }
        elseif ($text -match "^1\.1\.2 Motivation") { $pageMap["1.1.2 Motivation"] = "$adjPage" }
        elseif ($text -match "^1\.2 OBJECTIVES") { $pageMap["1.2 OBJECTIVES"] = "$adjPage" }
        elseif ($text -match "^1\.2\.1 Scope of the Work") { $pageMap["1.2.1 Scope of the Work"] = "$adjPage" }
        elseif ($text -match "^1\.3 OUTLINE OF REPORT") { $pageMap["1.3 OUTLINE OF REPORT"] = "$adjPage" }
        
        elseif ($text -cmatch "^CHAPTER 2\s+LITERATURE REVIEW") { $pageMap["2 LITERATURE REVIEW"] = "$adjPage" }
        elseif ($text -match "^2\.1 RELATED WORK") { $pageMap["2.1 RELATED WORK"] = "$adjPage" }
        elseif ($text -match "^2\.1\.1 IoT Network Security") { $pageMap["2.1.1 IoT Network Security and Wi-Fi Vulnerabilities"] = "$adjPage" }
        elseif ($text -match "^2\.1\.2 Machine Learning") { $pageMap["2.1.2 Machine Learning and Anomaly Detection in Network Traffic"] = "$adjPage" }
        elseif ($text -match "^2\.1\.3 Behavioral Profiling") { $pageMap["2.1.3 Behavioral Profiling and Multi-Dimensional Feature Analysis"] = "$adjPage" }
        elseif ($text -match "^2\.1\.4 Comparison of Existing") { $pageMap["2.1.4 Comparison of Existing Intrusion Detection Systems"] = "$adjPage" }
        elseif ($text -match "^2\.1\.5 Research Gaps") { $pageMap["2.1.5 Research Gaps Addressed by the Proposed System"] = "$adjPage" }
        elseif ($text -match "^2\.2 MATHEMATICAL BACKGROUND") { $pageMap["2.2 MATHEMATICAL BACKGROUND"] = "$adjPage" }
        elseif ($text -match "^2\.2\.1 Traffic Feature Formulations") { $pageMap["2.2.1 Traffic Feature Formulations"] = "$adjPage" }
        elseif ($text -match "^2\.2\.2 Dual Isolation Forest") { $pageMap["2.2.2 Dual Isolation Forest Theoretical Formulations"] = "$adjPage" }
        elseif ($text -match "^2\.2\.3 Performance and Classification") { $pageMap["2.2.3 Performance and Classification Evaluation Metrics"] = "$adjPage" }
        
        elseif ($text -cmatch "^CHAPTER 3\s+SYSTEM DESIGN AND METHODOLOGY") { $pageMap["3 SYSTEM DESIGN AND METHODOLOGY"] = "$adjPage" }
        elseif ($text -match "^3\.1 PROPOSED SYSTEM") { $pageMap["3.1 PROPOSED SYSTEM"] = "$adjPage" }
        elseif ($text -match "^3\.1\.1 Overall System Architecture") { $pageMap["3.1.1 Overall System Architecture"] = "$adjPage" }
        elseif ($text -match "^3\.1\.2 Hardware and Sensor Architecture") { $pageMap["3.1.2 Hardware and Sensor Architecture"] = "$adjPage" }
        elseif ($text -match "^3\.1\.3 Software Requirements") { $pageMap["3.1.3 Software Requirements and Technology Stack"] = "$adjPage" }
        elseif ($text -match "^3\.2 IMPLEMENTATION") { $pageMap["3.2 IMPLEMENTATION"] = "$adjPage" }
        elseif ($text -match "^3\.2\.1 Packet Capture") { $pageMap["3.2.1 Packet Capture and Traffic Window Generation"] = "$adjPage" }
        elseif ($text -match "^3\.2\.2 Dual-Detector Machine Learning") { $pageMap["3.2.2 Dual-Detector Machine Learning Pipeline"] = "$adjPage" }
        elseif ($text -match "^3\.2\.3 Deterministic Cyberattack") { $pageMap["3.2.3 Deterministic Cyberattack Signature Engine"] = "$adjPage" }
        elseif ($text -match "^3\.2\.4 Local Persistence and Cloud") { $pageMap["3.2.4 Local Persistence and Cloud Synchronization Architecture"] = "$adjPage" }
        elseif ($text -match "^3\.2\.5 Test Setup") { $pageMap["3.2.5 Test Setup and Verification Methodology"] = "$adjPage" }
        
        elseif ($text -cmatch "^CHAPTER 4\s+RESULTS AND DISCUSSION") { $pageMap["4 RESULTS AND DISCUSSION"] = "$adjPage" }
        elseif ($text -match "^4\.1 RESULTS") { $pageMap["4.1 RESULTS"] = "$adjPage" }
        elseif ($text -match "^4\.1\.1 Machine Learning Model Evaluation") { $pageMap["4.1.1 Machine Learning Model Evaluation"] = "$adjPage" }
        elseif ($text -match "^4\.1\.2 Attack Detection Performance") { $pageMap["4.1.2 Attack Detection Performance Across Threat Categories"] = "$adjPage" }
        elseif ($text -match "^4\.1\.3 Hardware Sensor Telemetry") { $pageMap["4.1.3 Hardware Sensor Telemetry and Latency Analysis"] = "$adjPage" }
        elseif ($text -match "^4\.1\.4 Cloud Synchronization") { $pageMap["4.1.4 Cloud Synchronization and Verification Audit"] = "$adjPage" }
        elseif ($text -match "^4\.2 DISCUSSION") { $pageMap["4.2 DISCUSSION"] = "$adjPage" }
        elseif ($text -match "^4\.2\.1 Comparative Performance") { $pageMap["4.2.1 Comparative Performance and Architectural Advantages"] = "$adjPage" }
        elseif ($text -match "^4\.2\.2 Real-World Operational Limitations") { $pageMap["4.2.2 Real-World Operational Limitations and Threats to Validity"] = "$adjPage" }
        
        elseif ($text -cmatch "^CHAPTER 5\s+CONCLUSION") { $pageMap["5 CONCLUSION"] = "$adjPage" }
        elseif ($text -match "^5\.1 REVIEW") { $pageMap["5.1 REVIEW"] = "$adjPage" }
        elseif ($text -match "^5\.2 CONCLUSIONS") { $pageMap["5.2 CONCLUSIONS"] = "$adjPage" }
        elseif ($text -match "^5\.3 RECOMMENDATIONS") { $pageMap["5.3 RECOMMENDATIONS FOR FUTURE WORK"] = "$adjPage" }
        
        elseif ($text -match "^REFERENCES") { if (-not $pageMap.ContainsKey("REFERENCES")) { $pageMap["REFERENCES"] = "$adjPage" } }
        elseif ($text -match "^APPENDICES") { if (-not $pageMap.ContainsKey("APPENDICES")) { $pageMap["APPENDICES"] = "$adjPage" } }
        elseif ($text -match "^APPENDIX 1") { $pageMap["APPENDIX 1  LISTING OF PROGRAMS"] = "$adjPage" }
        elseif ($text -match "^APPENDIX 2") { $pageMap["APPENDIX 2  RAW EXPERIMENTAL DATA"] = "$adjPage" }
        elseif ($text -match "^PUBLICATION DETAILS") { if (-not $pageMap.ContainsKey("PUBLICATION DETAILS")) { $pageMap["PUBLICATION DETAILS"] = "$adjPage" } }
        
        # Match Tables
        elseif ($text -match "^Table 2\.1") { $pageMap["Table 2.1"] = "$adjPage" }
        elseif ($text -match "^Table 2\.2") { $pageMap["Table 2.2"] = "$adjPage" }
        elseif ($text -match "^Table 3\.1") { $pageMap["Table 3.1"] = "$adjPage" }
        elseif ($text -match "^Table 3\.2") { $pageMap["Table 3.2"] = "$adjPage" }
        elseif ($text -match "^Table 3\.3") { $pageMap["Table 3.3"] = "$adjPage" }
        elseif ($text -match "^Table 4\.1") { $pageMap["Table 4.1"] = "$adjPage" }
        elseif ($text -match "^Table 4\.2") { $pageMap["Table 4.2"] = "$adjPage" }
        elseif ($text -match "^Table 4\.3") { $pageMap["Table 4.3"] = "$adjPage" }
        elseif ($text -match "^Table A 2\.1") { $pageMap["Table A 2.1"] = "$adjPage" }
        
        # Match Figures
        elseif ($text -match "^Figure 3\.1") { $pageMap["Figure 3.1"] = "$adjPage" }
        elseif ($text -match "^Figure 3\.2") { $pageMap["Figure 3.2"] = "$adjPage" }
        elseif ($text -match "^Figure 3\.3") { $pageMap["Figure 3.3"] = "$adjPage" }
        elseif ($text -match "^Figure 3\.4") { $pageMap["Figure 3.4"] = "$adjPage" }
        elseif ($text -match "^Figure 3\.5") { $pageMap["Figure 3.5"] = "$adjPage" }
        elseif ($text -match "^Figure 4\.1") { $pageMap["Figure 4.1"] = "$adjPage" }
        elseif ($text -match "^Figure 4\.2") { $pageMap["Figure 4.2"] = "$adjPage" }
    }
    
    Write-Host "`nCaptured Page Numbers:"
    $pageMap.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host "  $($_.Key) -> Page $($_.Value)"
    }
    
    # 2. Update Table 0 (Table of Contents)
    Write-Host "`nUpdating Table 0 (Table of Contents)..."
    $t0 = $doc.Tables.Item(1)
    for ($r = 2; $r -le $t0.Rows.Count; $r++) {
        $rawSNo = $t0.Cell($r, 1).Range.Text
        $rawTitle = $t0.Cell($r, 2).Range.Text
        $sNo = ($rawSNo -replace "[\r\n\x07]", "").Trim()
        $title = ($rawTitle -replace "[\r\n\x07]", "").Trim()
        $key = if ($sNo.Length -gt 0) { "$sNo $title" } else { $title }
        
        if ($pageMap.ContainsKey($key)) {
            $t0.Cell($r, 3).Range.Text = $pageMap[$key]
            Write-Host "  Bound TOC row ${r}: '$key' -> $($pageMap[$key])"
        } elseif ($pageMap.ContainsKey($title)) {
            $t0.Cell($r, 3).Range.Text = $pageMap[$title]
            Write-Host "  Bound TOC row ${r}: '$title' -> $($pageMap[$title])"
        } else {
            Write-Host "  Note: Kept default for TOC row ${r}: '$key'"
        }
    }
    
    # 3. Update Table 1 (List of Tables)
    Write-Host "`nUpdating Table 1 (List of Tables)..."
    $t1 = $doc.Tables.Item(2)
    for ($r = 2; $r -le $t1.Rows.Count; $r++) {
        $rawCap = $t1.Cell($r, 2).Range.Text
        $caption = ($rawCap -replace "[\r\n\x07]", "").Trim()
        $matched = $false
        foreach ($k in $pageMap.Keys) {
            if ($k -match "^Table" -and $caption.StartsWith($k)) {
                $t1.Cell($r, 3).Range.Text = $pageMap[$k]
                Write-Host "  Bound LOT row ${r}: '$k' -> $($pageMap[$k])"
                $matched = $true
                break
            }
        }
        if (-not $matched) {
            Write-Host "  Note: Kept default for LOT row ${r}: '$caption'"
        }
    }
    
    # 4. Update Table 2 (List of Figures)
    Write-Host "`nUpdating Table 2 (List of Figures)..."
    $t2 = $doc.Tables.Item(3)
    for ($r = 2; $r -le $t2.Rows.Count; $r++) {
        $rawCap = $t2.Cell($r, 2).Range.Text
        $caption = ($rawCap -replace "[\r\n\x07]", "").Trim()
        $matched = $false
        foreach ($k in $pageMap.Keys) {
            if ($k -match "^Figure" -and $caption.StartsWith($k)) {
                $t2.Cell($r, 3).Range.Text = $pageMap[$k]
                Write-Host "  Bound LOF row ${r}: '$k' -> $($pageMap[$k])"
                $matched = $true
                break
            }
        }
        if (-not $matched) {
            Write-Host "  Note: Kept default for LOF row ${r}: '$caption'"
        }
    }
    
    # 5. Save the updated Word document
    Write-Host "Saving updated Word document..."
    $doc.Save()
    
    # 6. Export to PDF
    Write-Host "Exporting to native PDF: $pdfPath..."
    # 17 = wdExportFormatPDF
    $doc.ExportAsFixedFormat($pdfPath, 17)
    
    Write-Host "PDF Export complete!"
    
    $totalPhysPages = $doc.ComputeStatistics(2) # 2 = wdStatisticPages
    Write-Host "Total document pages: $totalPhysPages"
    
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

Write-Host "Done! Verification files ready."
