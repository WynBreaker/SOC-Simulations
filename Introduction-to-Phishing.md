## Scenario 1: Introduction to Phishing

This is my first simulation using the **SOC Simulator on :contentReference[oaicite:0]{index=0}**, so I begin by exploring the available functionalities within the platform.  
All subsequent scenarios will focus purely on investigation and analysis and will not include this general overview section.

For this walkthrough, I used **:contentReference[oaicite:1]{index=1}** as my primary SIEM. After completing this room, I also repeated the same scenario using **ELK** and **Microsoft Sentinel**. The overall workflow is largely the same, with the main differences being the **query language** and how logs are filtered and visualized.

In the first screenshot:

screenshots/Introduction-to-Phishing/1.png


I am presented with the main SOC dashboard, which displays:

- Total alerts  
- Alerts marked as **True Positive**  
- Alerts marked as **False Positive**  
- Alert types  
- Open alerts  
- Time elapsed  

The **time elapsed** metric is particularly important, as it reflects a real SOC constraint — I am required to triage and resolve alerts **as efficiently as possible** while maintaining accuracy.

On the left-hand side of the interface, I can see several core functionalities:

- **Alert Queue:** Displays all incoming alerts (shown in `2.png`).  
- **SIEM:** Redirects me to the selected SIEM platform, in this case Splunk (shown in `6.png`).  
- **Analyst VM:** Provides multiple tools, including the *TryDetectMe* application, which I use to determine whether IPs, URLs, or attachments are malicious or benign (shown in `8.png`).  
- **Documentation:** Acts as a built-in guide for analysts, explaining how to triage alerts and score them correctly.  
  It also includes:
  - **Company Information:** Adds context by linking IP addresses to internal hosts for better reporting.  
  - **Asset Inventory:** Shows the company subnet, in this case `10.20.2.0/24`, meaning there are 254 hosts on the network (shown in `1.1.png` and `1.2.png`).  
- **Playbooks:** Two playbooks are available in this scenario, but only one was required — the **Phishing Playbook**.  
  This outlines the exact steps I need to follow to ensure consistent investigation and response procedures (shown in `5.png`).  
  Although I was unable to expand the playbook in the interface for some reason, I already understood the required workflow.

This scenario mainly serves as a baseline to understand how the SOC Simulator works before moving into more complex phishing investigations.
