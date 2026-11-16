$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open((Resolve-Path "Project_Report_CCNS.docx").Path)
    for ($idx = 1; $idx -le $doc.Paragraphs.Count; $idx++) {
        $p = $doc.Paragraphs.Item($idx)
        $t = $p.Range.Text.Trim()
        if ($t -match "^(CHAPTER 1|CHAPTER 2|CHAPTER 3|CHAPTER 4|CHAPTER 5|REFERENCES|APPENDICES|PUBLICATION|ABSTRACT)") {
            $adjPage = $p.Range.Information(1)  # wdActiveEndAdjustedPageNumber
            $secNum  = $p.Range.Information(2)  # wdActiveEndSectionNumber
            $physPage = $p.Range.Information(3) # wdActiveEndPageNumber
            Write-Host "PhysPage: $physPage, Sec: $secNum, AdjPage: $adjPage | $t"
        }
    }
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
}
