# WINSENTRY 🛡️

Advanced Windows security auditing and host-hardening tool with an interactive HTML5 dashboard, dynamic Security Scoring, and Baseline Delta Monitoring.

WINSENTRY is an enterprise-grade, lightweight defensive security scanner designed to analyze a system's security posture, verify OS-level hardening, and detect local anomalies. The tool compiles its forensic findings into an interactive, zero-dependency HTML5 dashboard designed with strict security controls to prevent local code execution.

---

### 🚀 What's New in This Update (v2.0)

* **Dynamic Security Posture Score (0–100%)**: Integrated a weighted hardening assessment engine (evaluating BitLocker, LSASS PPL, ScriptBlock Logging, CFA, UAC, and unsigned listening sockets).
* **Baseline Snapshot & Delta Monitoring**: Automatically tracks forensic differences across audit runs. Flags new open network ports, unauthorized local admin additions, startup tasks, and security regressions.
* **OS-Agnostic & Non-Interactive Engine**: Completely overhauled service and task interrogation to eliminate localization bugs. Added automated headless execution mode (`-Silent`) without UI hangs.
* **Accurate Port & Signature Mapping**: IPv4/IPv6 dual-stack listening ports are now intelligently aggregated and verified against kernel/catalog signatures without false alarms.

---

### Security Hardening Features (AppSec Audited)

Unlike standard script collection utilities, WINSENTRY is engineered with secure coding practices to mitigate common attack vectors associated with local reporting tools:

* **XSS & HTML Injection Mitigation**: All dynamic data harvested from the operating system (such as process names, system paths, and scheduled task commands) is strictly encoded using built-in HTML entity sanitization before rendering. This prevents malicious processes or files from executing arbitrary JavaScript within your browser context.
* **Localization Independence**: Avoids hardcoded localized string matching for system components, ensuring accurate reporting across all Windows display languages.
* **Resource Exhaustion & Infinite Loop Prevention**: The recursive file scanner explicitly ignores NTFS junctions, symlinks, and reparse points within temporary directories, eliminating the risk of denial-of-service (DoS) or memory exhaustion during directory traversal.
* **Error-Hardened Registry & Process Interrogation**: Low-level system queries are encapsulated in robust exception-handling blocks, ensuring the scanner gracefully degrades and reports access constraints rather than crashing.

---

### Core Audit Capabilities

* **Deep Shield Audit**: Verifies Windows Defender Real-Time Protection, Firewall across all active profiles, BitLocker volume encryption (via Storage/WMI), LSASS RunAsPPL protection, UAC consent policies, and Controlled Folder Access.
* **Network & Socket Mapping**: Dynamically resolves listening TCP sockets directly to their local IP bindings, PID, and owning Process Names with cryptographic signature verification.
* **Delta Forensics**: Compares previous state snapshots against current machine state to instantly identify newly spawned ports, persistence hooks, and account privilege escalations.
* **EDR Signature Verification**: Interrogates running network processes on disk and validates their Authenticode/Catalog signatures, highlighting unsigned or untrusted binaries.
* **Persistence Hunter**: Scans non-standard scheduled tasks and startup locations while filtering standard Windows OS paths.
* **Decoupled Configuration**: Readily adjusts scanning limits and scoring weights via an external `config.json` file.
* **Automated Deployment**: Includes an installer script to register weekly, elevated, silent background security scans.
* **Zero-Telemetry Privacy**: Operates entirely locally. No system data, network maps, or process lists ever leave the target machine.

---

### How to run

1. Open **PowerShell** as an **Administrator**.
2. Enable script execution for the current session:

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

3. Run the audit engine on-demand:

.\Run-Audit.ps1

4. Or register a weekly, hidden background scheduled task (automated silent audit):

.\install.ps1

5. The interactive `Report.html` dashboard will automatically launch in your default web browser (when run on-demand).

---

### Tech stack

* **PowerShell 5.1+** — algorithmic engine for OS interrogation, security event queries, and registry parsing.
* **HTML5 & CSS3** — responsive, grid-based dark-theme local dashboard layout.
* **Authenticode API** — cryptographic verification of running binary digital signatures.

---

### Project structure

- `.gitignore`
- `Checks.ps1`
- `config.json`
- `install.ps1`
- `README.md`
- `Run-Audit.ps1`

---

### Disclaimer

*This tool is intended for defensive security auditing and educational purposes only. Always ensure you have appropriate authorization before auditing any system.*
