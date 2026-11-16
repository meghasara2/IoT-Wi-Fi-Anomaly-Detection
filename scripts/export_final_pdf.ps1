# PowerShell Script: Update fields and export final PDF
# File: scripts/export_final_pdf.ps1

$ErrorActionPreference = "Stop"

$docxPath = (Resolve-Path "IoT_Network_Guard_Final_Project_Report.docx").Path
$pdfPath = [System.IO.Path]::ChangeExtension($docxPath, ".pdf")

Write-Host "Opening document in Word: $docxPath"
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = [Microsoft.Office.Interop.Word.WdAlertLevel]::wdAlertsNone

try {
    $doc = $word.Documents.Open($docxPath)
    Write-Host "Repaginating..."
    $doc.Repaginate()
    
    Write-Host "Updating document fields..."
    $doc.Fields.Update()
    
    Write-Host "Saving document..."
    $doc.Save()
    
    Write-Host "Exporting to PDF: $pdfPath..."
    $doc.ExportAsFixedFormat($pdfPath, 17) # 17 = wdExportFormatPDF
    
    $totalPhysPages = $doc.ComputeStatistics(2) # 2 = wdStatisticPages
    Write-Host "Export successful! Total pages: $totalPhysPages"
    
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

Write-Host "All tasks completed successfully!"
