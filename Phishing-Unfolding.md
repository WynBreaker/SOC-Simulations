## Scenario 2: Phishing Unfolding

This is the second SOC simulation I completed using the **SOC Simulator on TryHackMe**.  
For this scenario, I primarily used **Splunk SIEM**, although the simulation was later repeated using **ELK** and **Microsoft Sentinel**.

One key observation during setup was that log ingestion and data availability in **Splunk** and **ELK** occurred significantly faster compared to **Microsoft Sentinel**.

As the simulator functionality was covered extensively in Scenario 1, I will focus purely on investigation and alert handling in this walkthrough.

---

### Initial Overview

![Dashboard Overview](screenshots/Phishing-Unfolding/1.png)

*Figure 1 – SOC dashboard at the start of the Phishing Unfolding scenario.*

Upon entering the scenario, I noticed a documentation notification and proceeded to review it.

![Documentation & Asset Inventory](screenshots/Phishing-Unfolding/41.png)

*Figure 2 – Documentation section containing asset inventory, triage guidance, and reporting criteria.*

The documentation provided valuable context, including:

- Company asset inventory  
- Alert triage procedures  
- Alert classification criteria  
- Reporting guidelines  

The welcome page varies depending on the SIEM used. For example, when using **Microsoft Sentinel**, Azure credentials (username and password) are provided:

![Azure Credentials (Sentinel Only)](screenshots/Phishing-Unfolding/2.png)

*Figure 3 – Azure credentials shown when using Microsoft Sentinel.*

This credential page does not appear when using ELK or Splunk.

Another notable difference in this scenario was the absence of playbooks, which meant I relied strictly on SOC best practices and investigative reasoning.

---

### Alert 1 – Suspicious Banking Email (Low Severity)

After a few minutes, the first alert appeared.

![First Alert Arrival](screenshots/Phishing-Unfolding/3.png)

*Figure 4 – First alert appears in the alert queue (36 total alerts expected).*

The alert indicated a suspicious email requesting the recipient to urgently provide banking details.

![Suspicious Banking Email Alert](screenshots/Phishing-Unfolding/4.png)

*Figure 5 – Alert details showing a request for banking information.*

I pivoted to Splunk and searched for the recipient to locate the email event.

![Recipient Search in SIEM](screenshots/Phishing-Unfolding/4.1.png)

*Figure 6 – Email located in Splunk using recipient-based query.*

I specifically searched the recipient’s activity to determine whether:

- The user replied with sensitive information  
- Any attachments were involved  
- Any embedded URLs were present  

There were **no attachments**, **no URLs**, and **no reply containing sensitive data**. Because no malicious indicators were present and no user interaction occurred, I determined that this email resembled **spam rather than phishing**.

After monitoring briefly to confirm no further suspicious behavior, I wrote a report marking this alert as a **False Positive**, and the case was closed.

---

### Alert 2 – Suspicious Process on Host win-3459

Immediately after closing the previous case, another low-severity alert arrived.

![Suspicious Process Alert](screenshots/Phishing-Unfolding/5.png)

*Figure 7 – Alert indicating a suspicious process on host win-3459.*

I queried the host in Splunk to investigate the process tree.

![Process Investigation in SIEM](screenshots/Phishing-Unfolding/5.1.png)

*Figure 8 – Process lineage and event investigation in Splunk.*

My objective was to determine:

- Whether the process was spawned by a malicious parent  
- Whether it spawned additional suspicious child processes  
- Whether there were correlated abnormal events  

Everything appeared legitimate. The process originated from a valid parent process and no abnormal child processes were observed.

I documented the findings and classified the alert as a **False Positive**.

![False Positive Report – Process Alert](screenshots/Phishing-Unfolding/5.2.png)

*Figure 9 – Case report marking the alert as False Positive.*

---

### Alert 3 – Additional Suspicious Process

While working on the previous alert, another low-severity suspicious process alert arrived.

![Second Suspicious Process Alert](screenshots/Phishing-Unfolding/6.png)

*Figure 10 – Additional suspicious process alert in the queue.*

I noted the host details and searched for the process in Splunk.

![Process Search in SIEM](screenshots/Phishing-Unfolding/6.1.png)

*Figure 11 – SIEM search results for the flagged process.*

There were no additional correlated events beyond the single logged instance. I waited to observe whether further suspicious activity would occur, but none followed.

Given the absence of malicious behavior, unusual spawning activity, or lateral movement indicators, I classified this alert as a **False Positive**.

![False Positive Report – Second Process Alert](screenshots/Phishing-Unfolding/6.2.png)

*Figure 12 – Case report marking the second process alert as False Positive.*

---

*(To be continued in the next section.)*
