$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open((Resolve-Path "scratch/test_clean_saved2.docx").Path)
    $t0 = $doc.Tables.Item(1)
    Write-Host "Table 0 original rows: $($t0.Rows.Count)"
    
    # Check header
    Write-Host "Header: $($t0.Cell(1,1).Range.Text.Trim()) | $($t0.Cell(1,2).Range.Text.Trim()) | $($t0.Cell(1,3).Range.Text.Trim())"
    
    # Test adding a row
    $newRow = $t0.Rows.Add()
    $newRow.Cells.Item(1).Range.Text = "1"
    $newRow.Cells.Item(2).Range.Text = "INTRODUCTION"
    $newRow.Cells.Item(3).Range.Text = "1"
    
    Write-Host "Table 0 new rows: $($t0.Rows.Count)"
    $doc.Save()
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
}
