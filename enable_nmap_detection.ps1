# Hybrid SIEM - Enable Nmap Detection (Run ONCE as Administrator)
# Enables Windows Filtering Platform audit logging so that
# Nmap scans from Kali Linux appear in the Windows Security log
# as Event IDs 5152, 5153, 5154, 5155, 5156, 5157, 5158.

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Hybrid SIEM -- Nmap Detection Audit Policy Setup" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and choose Run as Administrator" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[1] Enabling Filtering Platform Connection auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

Write-Host "[2] Enabling Filtering Platform Packet Drop auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable

Write-Host "[3] Enabling Object Access category..." -ForegroundColor Yellow
auditpol /set /category:"Object Access" /success:enable /failure:enable

Write-Host ""
Write-Host "DONE - Audit policy updated." -ForegroundColor Green
Write-Host ""
Write-Host "Nmap scans from Kali will now generate:" -ForegroundColor White
Write-Host "  Event ID 5156 - Connection allowed  (nmap -sT connect scan)" -ForegroundColor Gray
Write-Host "  Event ID 5152 - Packet blocked      (nmap -sS SYN scan)" -ForegroundColor Gray
Write-Host "  Event ID 5157 - Connection blocked" -ForegroundColor Gray
Write-Host ""
Write-Host "Current audit policy status:" -ForegroundColor Cyan
Write-Host ""
auditpol /get /subcategory:"Filtering Platform Connection"
Write-Host ""
auditpol /get /subcategory:"Filtering Platform Packet Drop"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Restart Django:  cd d:\hybrid\backend  then  py manage.py runserver" -ForegroundColor White
Write-Host "  2. From Kali Linux: nmap -sT -p 1-1000 <your-windows-ip>" -ForegroundColor White
Write-Host "  3. Watch dashboard - scan appears in 5 seconds" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to close"
