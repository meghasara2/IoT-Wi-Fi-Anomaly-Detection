$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $docPath = (Resolve-Path "Project_Report_CCNS.docx").Path
    $doc = $word.Documents.Open($docPath)
    Write-Host "Opened document successfully: $($doc.Name)"
    Write-Host "Total paragraphs: $($doc.Paragraphs.Count)"
    
    # Check page number of a few paragraphs
    for ($i = 1; $i -le [Math]::Min(15, $doc.Paragraphs.Count); $i++) {
        $p = $doc.Paragraphs.Item($i)
        $text = $p.Range.Text.Trim()
        if ($text.Length -gt 0) {
            $pageNum = $p.Range.Information(3) # 3 = wdActiveEndPageNumber
            Write-Host "Para $i (Page $pageNum): $($text.Substring(0, [Math]::Min(50, $text.Length)))"
        }
    }
    
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
