$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open((Resolve-Path "IoT_Network_Guard_Final_Project_Report.docx").Path)
    Write-Host "Scanning paragraphs outside tables..."
    for ($idx = 1; $idx -le $doc.Paragraphs.Count; $idx++) {
        $p = $doc.Paragraphs.Item($idx)
        if ($p.Range.Tables.Count -eq 0) {
            $t = $p.Range.Text.Trim()
            if ($t -match "^(CHAPTER [1-5]|REFERENCES|APPENDICES|PUBLICATION DETAILS|APPENDIX [1-2]|Table|Figure|[1-5]\.[1-3])") {
                $adjPage = $p.Range.Information(1)
                $sec = $p.Range.Information(2)
                Write-Host "Sec $sec, AdjPage $adjPage : $t"
            }
        }
    }
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
}
