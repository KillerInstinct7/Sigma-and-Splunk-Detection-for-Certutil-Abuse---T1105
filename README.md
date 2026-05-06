# Overview
This project focuses on detecting potentially suspicious use of certutil.exe, a legitimate Windows binary commonly abused by attackers as a Living Off the Land Binary (LOLBAS). Specifically, this detection targets usage of the -urlcache and -verifyctl flags, which can be leveraged to download tools or payloads onto a victim system.

The behavior observed in this project aligns with MITRE ATT&CK Technique T1105 – Ingress Tool Transfer.

To validate the detection logic, Atomic Red Team was used to simulate adversary behavior, Sysmon telemetry was collected, and the resulting detection was operationalized in Splunk using both Sigma and SPL.


# MITRE ATT&CK Mapping
Tactic	                   Technique	                    ID
Command and Control	       Ingress Tool Transfer	        T1105


# Lab Environment / Tooling
- Windows 10 Host
- Sysmon
- Splunk Enterprise
- Sigma
- Atomic Red Team
- Sysmon Event ID 1 (Process Creation)


# Detection Logic
This detection identifies execution of certutil.exe using the -urlcache or -verifyctl flags, which may indicate file transfer behavior using a trusted Windows utility.

The primary goal of the detection was to focus on behavioral indicators rather than static Indicators of Compromise (IoCs).

Core Detection Logic:
- certutil.exe process execution
- Command line containing:
    * -urlcache
    * OR -verifyctl
 
Contextual Enrichment Considerations:
- The following behaviors may increase confidence of malicious activity:
    * Use of -split
    * Use of -f
    * Interaction with external URLs
    * Writing files to user-writable directories
    * Follow-on execution activity after download
    * Invocation from PowerShell or cmd.exe

- These enrichment opportunities were intentionally not required as core detection logic in order to avoid overfitting the rule to a single test case and to maintain broader behavioral coverage.


# Sigma Rule
title: Suspicious Certutil.exe Behavior

id: 76c5568e-9358-4b07-9a46-66e247cb397b

status: experimental

description: Detects certutil.exe execution using the -urlcache or -verifyctl flags, which may indicate file transfer behavior using a legitimate Windows binary.

references:
  - https://attack.mitre.org/techniques/T1105/

author: Matthew Mayne

date: '2026-05-05'

date modified: '2026-05-06'

tags:
  - attack.command_and_control
  - attack.t1105

logsource:
  product: windows
  category: process_creation

detection:

  selection1:
  
    Image|endswith: '\certutil.exe'

    
  selection2:
  
    CommandLine|contains:
    
      - '-urlcache'
      
      - '-verifyctl'

      
  condition: selection1 and selection2
  
falsepositives:

  - Internal certificate retrieval, enterprise PKI usage, and/or software updating mechanisms.


level: medium


# SPL Query
index="detectionlab_3" Image="*certutil.exe" (CommandLine="*-urlcache*" OR CommandLine="*-verifyctl*")

This SPL query was used to operationalize the Sigma logic within Splunk and generate alerts for suspicious certutil activity.


# Validation
- Detection validation was performed using the Atomic Red Team T1105 test module.

Validation Workflow:
1. Executed Atomic Red Team T1105 tests involving certutil-based file transfer behavior
2. Collected Sysmon Event ID 1 telemetry
3. Reviewed process creation logs in Event Viewer and Splunk
4. Built and refined Sigma detection logic
5. Translated the Sigma rule into SPL
6. Established alerting within Splunk
7. Validated detection hits against generated telemetry

During testing, additional process activity and downstream execution behavior were observed, reinforcing the importance of behavioral analysis and telemetry correlation when building detections.


# False Positives/Tuning Considerations
Because certutil.exe is a legitimate Windows utility, false positives are possible in environments utilizing:
- Internal certificate infrastructure
- Certificate trust validation
- Administrative PKI troubleshooting
- Software deployment workflows

Potential tuning opportunities include:
- Allowlisting known internal certificate servers or domains
- Allowlisting approved administrative systems
- Increasing alert severity when:
    * External URLs are involved
    * User-writable paths are used
    * Executable/script files are downloaded
    * Suspicious parent processes are observed


# Future Improvements
Potential future enhancements to this project include:
- Correlation with downstream process execution
- Detection of suspicious output file extensions
- Risk scoring based on contextual enrichment
- Additional SPL tuning for enterprise environments
- Parent-child process correlation logic
- Integration into Detection-as-Code pipelines


# Key Takeaways
This project reinforced several important detection engineering concepts:
- Legitimate administrative tools can be abused by attackers
- Behavioral detections are often more resilient than static IoCs
- Detection engineering requires balancing coverage and false positives
- Validation against real telemetry is critical
- Operational context matters when designing alerts
