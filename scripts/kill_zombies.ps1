# =============================================================================
# Force-kill any lingering Python, TShark, or Dumpcap processes
# =============================================================================
Write-Host "Scanning for orphaned IoT / TShark processes..." -ForegroundColor Cyan

$processNames = @("dumpcap", "tshark", "python")
$found = 0

foreach ($pName in $processNames) {
    $procs = Get-Process -Name $pName -ErrorAction SilentlyContinue
    if ($procs) {
        foreach ($p in $procs) {
            # Skip current PowerShell process or Antigravity
            if ($p.Id -ne $PID) {
                Write-Host "Terminating $($p.ProcessName) (PID $($p.Id))..." -ForegroundColor Yellow
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                $found++
            }
        }
    }
}

if ($found -eq 0) {
    Write-Host "No orphaned processes found. System is clean." -ForegroundColor Green
} else {
    Write-Host "Terminated $found orphaned process(es)." -ForegroundColor Green
}
