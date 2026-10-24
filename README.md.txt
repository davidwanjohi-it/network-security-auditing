# DevSecOps & Security Engineering Lab — Infrastructure, SIEM & Automation
## Author: David Wan (Independent Architecture & Implementation Platform)

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
    CREATE USER 'jdoe'@'10.0.2.30' IDENTIFIED BY 'SecurePassword123!';
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
2.  **Overcame Username Identity Lockouts:** Diagnosed an authentication block where dropdown pickers frozen within the UI threw errors. Recognized that the Atlassian Cloud API deprecated legacy string username calls. Remedied the problem by changing the configuration profile username key from the display alias (`davidwan476`) to the full administrator registration email (`davidjk13b@gmail.com`).
3.  **Remedied Host Metadata Mismatch (Case-Sensitivity Flaw):** Discovered an event-matching issue where the brute-force correlation rule returned 0 results despite the workstation generating failures. Isolated the flaw to Splunk's strict case sensitivity applied to host strings, which expected `DAVID-PC01` instead of `david-pc01`. Fixed the analytics search by using case-insensitive wildcard patterns (`host="*david-pc01*"`).
4.  **Debugged Invalid Search Commands:** Cleared a critical UI syntax crash (`Unknown search command 'appendruns'`) introduced via file corruptions inside the `savedsearches.conf` editing modal. Stripped the invalid query fragments and deployed a pristine, performance-optimized one-line query to stabilize system monitoring logs.

---

## 4. Key Hands-On Skills Mastered

*   **Infrastructure Engineering:** Virtualized sandboxing, advanced Windows/Linux administrative management, network interface routing, and host security isolation.
*   **SIEM Administration & Analysis:** Indexing pipeline deployment, advanced log parsing, fields mapping customization, and real-time behavioral correlation queries using SPL.
*   **Database Security Architecture:** Linux database engine administration, remote binding restriction configurations, and network-scoped access control lists (ACLs).
*   **Security Automation & Orchestration (SOAR):** Programmatic webhook configuration, REST API integrations, dynamic token management, and structured ticket life-cycle synchronization.
