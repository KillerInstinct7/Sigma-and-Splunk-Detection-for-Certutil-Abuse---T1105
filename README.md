# Sigma-and-Splunk-Detection-for-Certutil-Abuse---T1105
This project detects certutil.exe execution using the -urlcache or -verifyctl flags, which may align to MITRE attack ID T1105 - ingress tool transfer.  I started by generating logs via the T1105 Atomic Red Team module, proceeded to build the detection in Sigma, then translated it into SPL and established it as an alert in Splunk.
