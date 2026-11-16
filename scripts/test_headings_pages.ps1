$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open((Resolve-Path "Project_Report_CCNS.docx").Path)
    for ($idx = 1; $idx -le $doc.Paragraphs.Count; $idx++) {
        $p = $doc.Paragraphs.Item($idx)
        $t = $p.Range.Text.Trim()
        if ($t -match "^(CHAPTER|REFERENCES|APPENDICES|PUBLICATION|ABSTRACT|TABLE OF CONTENTS|LIST OF)") {
            $page = $p.Range.Information(3) # wdActiveEndPageNumber
            $sec = $p.Range.Information(1)  # wdActiveEndSectionNumber
            Write-Host "Sec $sec, Page $page : $t"
        }
    }
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
}
