
# Advanced Network Interception, TLS Decryption, and EDR Simulation Lab

An isolated, dual-node virtual laboratory environment designed to analyze cleartext data leakage, execute local network topology interception, construct an active HTTPS/TLS decryption pipeline, automate payload file extraction, and engineer host-based detection capabilities against trust-store exploitation.

##  Architectural Overview
This laboratory is built inside a fully isolated virtual network infrastructure to guarantee zero packet leakage onto external production networks.

* **Network Fabric:** VirtualBox 7.x global NAT Network (`10.0.2.0/24`) with internal DHCP allocation.
* **Attacker Node:** Kali Linux rolling release (`10.0.2.15`).
* **Victim Node:** Windows 10 Pro environment (`10.0.2.3`).
* **Hardening Baseline:** Selective inbound ICMPv4 exceptions enabled on the Windows host firewall to validate cross-segment communication lanes.

---

##  Project Phases & Implementations

### Phase 1: Cleartext Credential Harvesting (FTP Auditing)
To prove the inherent flaw of legacy, unencrypted protocols, a local FTP Server was provisioned on the Windows host via Internet Information Services (IIS) without SSL requirements. 

Using **Wireshark** on Kali Linux, a passive capture filter was bound to the active interface. Traffic analysis verified that authentication details are passed over the wire in plain, readable text:

```text
[Wireshark TCP Stream Reassembly]
220 Microsoft FTP Service
USER labuser
331 Password required for labuser.
PASS Password123!
230 User logged in.
```

### Phase 2: Local Network MITM Interception (HTTP Phase)
Before jumping to proxy architectures, a local Man-in-the-Middle (MITM) attack was executed to intercept live web transactions over standard unencrypted **HTTP**.
1. Initialized **Bettercap** on the Kali node bound to the local interface (`sudo bettercap -iface eth0`).
2. Executed dynamic active network discovery (`net.probe on`) to map the sandbox topology and isolate the Windows 10 host target (`10.0.2.3`).
3. Formulated bidirectional route poisoning by setting the target variables and enabling full-duplex ARP spoofing (`set arp.spoof.targets 10.0.2.3`, `set arp.spoof.fullduplex true`, `arp.spoof on`).
4. **The Cryptographic Ceiling:** While unencrypted HTTP packets and credentials were successfully captured in plain text during web form submissions, navigating to encrypted **HTTPS** portals immediately blinded the sniffer. The underlying TLS layer reduced the captured payloads to completely unreadable, scrambled binary data blocks.

### Phase 3: Active HTTPS/TLS Decryption Pipeline
To overcome the limitations found in Phase 2 and gain visibility into encrypted streams, a corporate-grade proxy model was engineered:
1. Deployed an active interception web dashboard in Kali Linux via `mitmproxy` (`mitmweb`) listening on port `8080`.
2. Configured the Windows 10 manual network proxy routing directly into the Kali node.
3. Injected a custom Root Certificate Authority (`mitmproxy-ca-cert.p12`) into the Windows **Trusted Root Certification Authorities** machine store.
4. Filtered active traffic flows for HTTP `POST` methods to capture secure account creation payloads (e.g., `://pinterest.com`), successfully bypassing the TLS layer and exposing registration metrics in cleartext.

### Phase 4: Programmatic File Extraction & Network Automation
To move past manual GUI inspection tools, a Python automation plugin script (`extractor.py`) was engineered using the `mitmproxy` API hooks to automatically harvest binary assets in-flight.
1. Formulated an event-driven `response()` function to programmatically monitor all inbound gateway responses passing through the proxy socket layer.
2. Parsed network header metadata to isolate specific MIME application types (`application/pdf`, `application/zip`) and attachment properties.
3. Automated the extraction of raw binary payload byte arrays directly out of the memory buffers and wrote them natively to the local file system (`~/intercepted_files`), successfully recovering complete uncorrupted multi-megabyte PDF assets.

### Phase 5: Defensive Engineering & Host-Based EDR Scripting
To close the auditing loop, a forensic analysis was conducted on Windows to trace the markers left behind by certificate injection. A lightweight, simulated **Endpoint Detection and Response (EDR)** engine was written in PowerShell to monitor the system registry and instantly alert security teams of unauthorized root trust modifications.

---

##  Included Scripts

### 1. Programmatic File Extraction Automation Engine (`extractor.py`)
Run this on your Kali Linux instance using `mitmweb -s extractor.py` to automatically capture and write file downloads to your local storage directory:

```python
import os
from mitmproxy import http

# Define the absolute local path on your Kali machine to store intercepted files
TARGET_DIRECTORY = os.path.expanduser("~/intercepted_files")

# Ensure the output repository directory exists on disk
if not os.path.exists(TARGET_DIRECTORY):
    os.makedirs(TARGET_DIRECTORY)

def response(flow: http.HTTPFlow) -> None:
    """Triggered automatically every time a network response passes through the proxy wire."""
    content_disposition = flow.response.headers.get("Content-Disposition", "")
    
    # Check if the transaction represents a binary application download or an explicit file attachment
    if "attachment" in content_disposition or "application/" in flow.response.headers.get("Content-Type", ""):
        
        # Parse the URL path to isolate the original file name
        url_path = flow.request.path.split("?")[0]
        filename = url_path.split("/")[-1]
        
        # Enforce a secure fallback filename if the path parsing returns blank parameters
        if not filename or len(filename) > 255:
            filename = f"downloaded_payload_{int(flow.request.timestamp_start)}"

        # Construct the absolute output destination path
        output_filepath = os.path.join(TARGET_DIRECTORY, filename)
        
        try:
            # Extract the raw response body byte array and write it directly to the local filesystem
            with open(output_filepath, "wb") as file_writer:
                file_writer.write(flow.response.content)
            
            print(f"\n[★ FILE AUDIT SYSTEM] Intercepted payload downpour!")
            print(f"    Origin Domain: {flow.request.host}")
            print(f"    Extracted File: {filename}")
            print(f"    Local Lab Storage Path: {output_filepath}\n")
            
        except IOError as error:
            print(f"[!] File write anomaly encountered: {error}")
```

### 2. Host-Based EDR Registry Watcher (`security_monitor.ps1`)
Run this on the Windows 10 victim node within an Administrator PowerShell window to detect unauthorized proxy certificate installations in real-time:

```powershell
Write-Host "[*] EDR Registry Monitor Active: Watching Trusted Roots... Press Ctrl+C to stop." -ForegroundColor Cyan
\$Path = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"

while (\$true) {
    Check = Get-ChildItem -Path Path -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty \$_.PsPath).FriendlyName -like "*mitmproxy*"
    }
    if (\$Check) {
        Write-Host "`n[!!!] REGISTRY SECURITY ALERT [!!!]" -ForegroundColor Red
        Write-Host "    Unauthorized Root Certificate Registry Injection!" -ForegroundColor Yellow
        Write-Host "    Target Key: $Path" -ForegroundColor White
        Write-Host "    Action Required: An active intercept tool has altered system trust stores.`n" -ForegroundColor LightRed
        break
    }
    Start-Sleep -Seconds 1
}
```

### 3. Network Passive Ping Monitor (`ping_monitor.py`)
Run this script on the Kali Linux node using `sudo python3 ping_monitor.py` to trace raw, decrypted ICMP transactions over the local wire using Scapy:

```python
from scapy.all import sniff, ICMP, IP

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet[ICMP].type == 8:
            print(f"[➔] PING REQUEST: {src_ip} is pinging {dst_ip}")
        elif packet[ICMP].type == 0:
            print(f"[✔] PING REPLY:   {dst_ip} responded to {src_ip}")

print("[*] Actively monitoring the NAT Network for ping traffic... Press Ctrl+C to stop.")
sniff(filter="icmp", store=0, prn=process_packet)
```

---

##  Lab Decommissioning & Cleanup
To restore the laboratory nodes to their pristine, untampered baseline:
1. **Proxy Teardown:** Disabled the Windows manual proxy server toggle.
2. **Certificate Eviction:** Opened `certmgr.msc` on Windows and permanently deleted `mitmproxy` from the Root Certificate directory.
3. **Session Purge:** Cleanly exited all socket-binding background terminals (`mitmweb`, `bettercap`) via standard execution interrupts (`Ctrl + C`).

---

##  Professional Competencies Gained
* Advanced Sandbox Environment Modeling (VirtualBox Expert Layouts).
* Cryptographic Key Management & Root Certificate Authority Mapping.
* Deep Packet Inspection & Traffic Reassembly (Wireshark).
* Network Automation Scripting & Inline Programmatic Interception (mitmproxy Python API).
* Proactive Endpoint Hardening & SIEM/EDR Automation (PowerShell & Python).

================================================================================================================
# DevSecOps & Security Engineering Lab — Infrastructure, SIEM & Automation
## Author: David Wanjohi (Independent Architecture & Implementation Platform)

A highly scalable, multi-component Security Engineering platform built inside an isolated Oracle VirtualBox hypervisor network segment. This project houses an enterprise real-time event correlation framework monitoring critical endpoint telemetry, parsing structured data pipelines into a native Splunk SIEM engine, and deploying programmatic Python/Modular webhook automations to orchestrate instant incident lifecycle tracks on an Atlassian Jira Cloud dashboard.

---

## 1. Architectural Topology & Environment Matrix

The infrastructure operates entirely under a dedicated host-only virtual network switch (`10.0.2.0/24`) behind a simulated gateway to guarantee control and network security isolation during attack simulation sequences.

*   **Endpoint Workstation (`10.0.2.30`):** Windows 10 Enterprise (`DAVID-PC01`). Configured with advanced OS logging capabilities, System Monitor (Sysmon) binaries, a local MySQL Workbench deployment, and a dedicated Splunk Universal Forwarder agent.
*   **Central SIEM & Database Engine (`10.0.2.10`):** Ubuntu Server hosting a standalone native Splunk Enterprise instance listening on port TCP `9997` for log collection streams, as well as the remote corporate MySQL Server instance.
*   **Target Ticketing Gateway Platform:** Atlassian Jira Service Management Cloud Sandbox instance (`https://atlassian.net`) mapped to project key `SOC`.

---

## 2. Core Engineering Modules & Hands-On Implementations

### A. Windows Telemetry Optimization & Log Shipping
*   **Sysmon & Event Log Tuning:** Implemented customized configuration XML schemas to strip out noise while maximizing capture fidelity for advanced file system mutations, memory injection hooks, and process telemetry.
*   **Splunk Universal Forwarder Engineering:** Configured local `inputs.conf` files to securely capture local channels (`WinEventLog:Security`, `WinEventLog:Microsoft-Windows-Sysmon/Operational`) and stream structured arrays continuously to the Ubuntu SIEM collector index.

### B. Relational Database Hardening & Remote MySQL Access
*   **Database Schema Engineering:** Built and structured corporate schema foundations (`corporate_records`) containing relational data sets (`employees`) to simulate sensitive, corporate business records.
*   **Remote Security Provisioning:** Hardened the Ubuntu MySQL daemon configuration by re-binding interface constraints from local loopbacks (`127.0.0.1`) to corporate subnet boundaries (`0.0.0.0`).
*   **Secure Access Controls:** Configured remote administrative privileges using specific network scopes to restrict workstation incoming sessions to the verified client endpoint IP:
    ```sql
    CREATE USER 'jdoe'@'10.0.2.30' IDENTIFIED BY '********';
    GRANT SELECT, INSERT, UPDATE ON corporate_records.* TO 'jdoe'@'10.0.2.30';
    FLUSH PRIVILEGES;
    ```
*   **Client Verification:** Successfully connected the remote workstation application client (`MySQL Workbench`) from the Windows 10 host directly to port `3306` on the Ubuntu database hub.

### C. Splunk Analytics & Advanced Real-Time Correlation Queries
*   **Analytical Profiling Search:** Formulated optimized, case-insensitive index searches using metadata wildcard filtering (`host="*david-pc01*"`) to normalize Windows log data models.
*   **Logic Rule Construction:** Engineered a robust SPL multi-field tracking algorithm designed to isolate workstation brute-force trends. The logic clusters targeted system user objects within an active temporal window, ignoring noisy machine accounts:
    ```splunk
    index=windows_logs host="*david-pc01*" EventCode=4625| eval actual_user=coalesce(TargetUserName, SubjectUserName, Account_Name) | stats count, values(actual_user) as targeted_users by host | search count >= 3
    ```

### D. Automated Ticketing & Python Action Pipelines
*   **Modular Webhook Integration:** Installed and configured the Atlassian Jira Service Desk Modular Alert Framework within Splunk's environment (`/opt/splunk/etc/apps/`).
*   **Cloud Platform Mapping:** Tied local configurations directly to Jira Cloud’s REST API endpoints using programmatic Atlassian access tokens.
*   **Dynamic Data Transport:** Structured automated parameters inside backend `savedsearches.conf` files to cleanly translate real-time metadata rows (`$result.host$`, `$result.count$`, `$result.targeted_users$`) into structured inbound IT Service Management payloads, populating live security tracking tickets instantly.

---

## 3. High-Value Troubleshooting & Root-Cause Analysis Actions

A core achievement of this project was independent debugging of intricate validation and syntax failures across the event lifecycle pipeline:

1.  **Resolved API Synchronization Error (Jira Validation Crash):** Identified an execution failure where Splunk logged an internal system loop error: `HTTP Error=400 ... 'issuetype':'Specify a valid issue type'`. Traced the root cause to a mismatch where configuration stanzas misidentified parameter variables as `jira_service_desk_simple_addon` instead of the required `jira_service_desk` modular fields. Reconfigured the parameters and schema keys, clearing the backlogged queue entries instantly.
2.  **Overcame Username Identity Lockouts:** Diagnosed an authentication block where dropdown pickers frozen within the UI threw errors. Recognized that the Atlassian Cloud API deprecated legacy string username calls. Remedied the problem by changing the configuration profile username key from the display alias  to the full administrator registration email .
3.  **Remedied Host Metadata Mismatch (Case-Sensitivity Flaw):** Discovered an event-matching issue where the brute-force correlation rule returned 0 results despite the workstation generating failures. Isolated the flaw to Splunk's strict case sensitivity applied to host strings, which expected `DAVID-PC01` instead of `david-pc01`. Fixed the analytics search by using case-insensitive wildcard patterns (`host="*david-pc01*"`).
4.  **Debugged Invalid Search Commands:** Cleared a critical UI syntax crash (`Unknown search command 'appendruns'`) introduced via file corruptions inside the `savedsearches.conf` editing modal. Stripped the invalid query fragments and deployed a pristine, performance-optimized one-line query to stabilize system monitoring logs.

---

## 4. Key Hands-On Skills Mastered

*   **Infrastructure Engineering:** Virtualized sandboxing, advanced Windows/Linux administrative management, network interface routing, and host security isolation.
*   **SIEM Administration & Analysis:** Indexing pipeline deployment, advanced log parsing, fields mapping customization, and real-time behavioral correlation queries using SPL.
*   **Database Security Architecture:** Linux database engine administration, remote binding restriction configurations, and network-scoped access control lists (ACLs).
*   **Security Automation & Orchestration (SOAR):** Programmatic webhook configuration, REST API integrations, dynamic token management, and structured ticket life-cycle synchronization.

## 4. Conclusion

This portfolio demonstrates practical work across SIEM monitoring, Windows event collection, incident ticket automation, database administration, network security auditing, traffic analysis, TLS interception, and endpoint monitoring.

The projects emphasize hands-on implementation, troubleshooting, security analysis, and reproducible laboratory evidence to support continued development in DevSecOps and Security Engineering.
