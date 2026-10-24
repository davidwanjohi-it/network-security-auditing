<#
================================================================================
SCRIPT OBJECTIVE
================================================================================
The objective of the security_monitor.ps1 script is to simulate a host-based
Endpoint Detection and Response (EDR) or Security Information and Event Management 
(SIEM) monitoring solution. It acts as an automated integrity monitor for the 
Windows host system's cryptographic trust configuration.

Specifically, it achieves three goals:
1. Validates Trust Store Integrity: It continuously tracks the state of the 
   local machine's Trusted Root Certification Authorities database to detect 
   unauthorized, external modifications.
2. Identifies Key Interception IoCs: It targets and alerts on specific Indicators 
   of Compromise (IoCs)—such as the injection of a 'mitmproxy' certificate—which 
   signal that an active Man-in-the-Middle (MITM) pipeline has been deployed.
3. Automates Security Incident Response: It surfaces immediate, high-severity 
   visual warnings to the console interface when anomalies are detected, mimicking 
   how an enterprise defense agent reports critical security events.
================================================================================
#>

# Print initialization banner to the console interface
Write-Host "[*] EDR Registry Monitor Active: Watching Trusted Roots... Press Ctrl+C to stop." -ForegroundColor Cyan

# Define the precise registry path where Windows locks local machine Root Certificate storage configurations
\$Path = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"

# Initialize an infinite monitoring loop to check for real-time unauthorized system trust shifts
while (\$true) {
    
    # Query the targeted registry keys while suppressing errors if paths are temporarily locked by the OS
    # Use Where-Object to dynamically parse the list and search for an entry containing the 'mitmproxy' FriendlyName string
    Check = Get-ChildItem -Path Path -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty \$_.PsPath).FriendlyName -like "*mitmproxy*"
    }
    
    # If the check returns true (indicating the proxy certificate signature has been successfully identified)
    if (\$Check) {
        # Trigger an Endpoint Detection and Response (EDR) style high-severity visual terminal alarm
        Write-Host "`n[!!!] REGISTRY SECURITY ALERT [!!!]" -ForegroundColor Red
        Write-Host "    Unauthorized Root Certificate Registry Injection!" -ForegroundColor Yellow
        Write-Host "    Target Key: $Path" -ForegroundColor White
        Write-Host "    Action Required: An active intercept tool has altered system trust stores.`n" -ForegroundColor LightRed
        
        # Terminate the loop session to freeze the monitor output on the detected security breach logs
        break
    }
    
    # Rest the CPU cycle for 1 second before executing the next diagnostic registry validation sweep
    Start-Sleep -Seconds 1
}
