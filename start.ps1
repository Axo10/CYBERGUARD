# CYBERGUARD PowerShell Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  CYBERGUARD: AI-Powered Cyber Defence Operations Center" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$pythonExe = "C:\Users\Aryan Jena\AppData\Local\Programs\Python\Python311\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "python"
}

Write-Host "[*] Starting Flask backend server on http://127.0.0.1:5000..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $pythonExe -ArgumentList "backend\run.py" -PassThru

Start-Sleep -Seconds 3

Write-Host "[*] Launching CYBERGUARD Command Dashboard..." -ForegroundColor Green
Start-Process "http://127.0.0.1:5000"

Write-Host "[+] CYBERGUARD is running! (Process ID: $($proc.Id))" -ForegroundColor Green
Write-Host "    Press Enter to stop the backend server..."
Read-Host
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
