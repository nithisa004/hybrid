@echo off
echo.
echo ===================================================
echo  Hybrid SIEM -- Enable Nmap Detection Audit Policy
echo ===================================================
echo.

:: Enable Filtering Platform Connection (generates Event 5152-5158)
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
if %errorlevel%==0 (
    echo [OK] Filtering Platform Connection auditing ENABLED
) else (
    echo [FAIL] Could not set audit policy. Are you running as Administrator?
    pause
    exit /b 1
)

:: Enable Filtering Platform Packet Drop
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
if %errorlevel%==0 (
    echo [OK] Filtering Platform Packet Drop auditing ENABLED
) else (
    echo [WARN] Packet Drop auditing failed - continuing
)

echo.
echo Current status:
auditpol /get /subcategory:"Filtering Platform Connection"
echo.
echo ===================================================
echo  SUCCESS! Nmap scans from Kali will now be logged
echo  as Event IDs 5152-5157 in Windows Security log.
echo.
echo  Next steps:
echo    1. Restart Django server (Ctrl+C then: py manage.py runserver)
echo    2. From Kali: nmap -sT -p 1-1000 YOUR_WINDOWS_IP
echo    3. Watch dashboard - scan appears within 5 seconds
echo ===================================================
echo.
pause
