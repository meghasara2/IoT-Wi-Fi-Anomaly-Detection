try {
    $word = New-Object -ComObject Word.Application
    Write-Host "Word Version: $($word.Version)"
    $word.Quit()
} catch {
    Write-Host "Word COM Error: $($_.Exception.Message)"
}
