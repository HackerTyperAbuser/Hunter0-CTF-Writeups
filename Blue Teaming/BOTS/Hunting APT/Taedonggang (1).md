# Hunting an APT with Splunk: Initial Access

![](img/Pasted%20image%2020241020123936.png)
Scenario: Frothly a brewing beverage company has just been attacked and it is our job to investigate the incident and hunt threats. Incident occurred in August 2017.
Environment:
![](img/Pasted%20image%2020241020124635.png)
## T1566.001 Phishing: Spearphishing Attachment
Source: https://attack.mitre.org/techniques/T1566/001/
MITRE ATT&CK technique that outlines the sending of spearphishing emails with malicious attachments in attempt to gain initial access to victim systems. Adversary attach a file that relies on _**User Execution**_ to gain execution. 

To investigate, some hypothesis are outlined:
- What data sources should we look for in mail traffic?
- Do we have visibility into what email attachments are being received?
- Are there specific kinds of attachments that we should be hunting for?
- What information should we look for when found attachments? (Sender, recipient, subject, message...)
- Do we see the same attributes in other emails?
- Are there any prior spearphishing attempts that were unsuccessful?
### Splunk Analysis
Interesting Protocol for mail traffic: SMTP
`| metadata type=sourcetypes index=botsv2`
![](img/Pasted%20image%2020241020130648.png)
There are some SMTP entries for which we can begin our analysis.
![](img/Pasted%20image%2020241020131604.png)
Interesting note, there is a massive spike of 20th August 2017 (assumed time where the attack starts).
Attachment fields contains, information of attachments sent through SMTP.
![](img/Pasted%20image%2020241020131818.png)
In particular file invoice.zip and Malware Alert Text.txt is interesting.
Information about the email containing invoice.zip 
![](img/Pasted%20image%2020241020132613.png)
Information on the attachment invoice.zip
![](img/Pasted%20image%2020241020133637.png)
![](img/Pasted%20image%2020241020133837.png)
- Sender: Jim Smith <jsmith@urinalysis.com>
- 4 recipient, all at froth.ly organization.
- 4 source ip: 104.47.37.62, 104.47.38.87, 104.47.41.43, 104.46.42.76 (all part of the same subnet)
- The subject, file_size and MD5 hash for all 4 recipient are the same.
- These emails were sent on August 23rd 2017, eliminating one of our previous assumptions of the attack occurring on August 20th 2017.
- Sender IP address of 185.83.51.21 was consistent across all recipient.
![](img/Pasted%20image%2020241020134231.png)

Information on Malware Alert Text.txt
![](img/Pasted%20image%2020241020140744.png)
The sender Jim Smith have attempted to send emails to the same recipient on August 10th, 2017. Malware Alert Text.txt content is revealed when decoded.
![](img/Pasted%20image%2020241020141638.png)
Outlook seem to have prevented the attachment the first time, however, it went through the second time.
This confirms that invoice.zip is a Trojan, which makes user Jim Smith a person of interest.
### OSINT 
From Splunk analysis we can attempt to retrieve some more information from OSINT.
Decoding the content of invoice.zip reveals invoice.doc which is contained in the .zip archive.
![](img/Pasted%20image%2020241020133721.png)
Hash analysis did not reveal much
![](img/Pasted%20image%2020241020135009.png)


IP analysis, for source address reveals the Microsoft Office service
![](img/Pasted%20image%2020241020135245.png)
The 185.83.51.21 address reveals a different address
![](img/Pasted%20image%2020241020135356.png)
However, it seems the attacker have leverage a different service (ymlp.net) to send the spearphishing email. This essentially outline MITRE ATT&CK T1583.006 Acquire Infrastructure: Web Services.
![](img/Pasted%20image%2020241020135604.png)
Whois lookup on urinalysis.com didn't reveal any interesting information either.
![](img/Pasted%20image%2020241020140105.png)
## T1204.002 User Execution: Malicious File
Source: https://attack.mitre.org/techniques/T1204/002/
Adversary rely on user opening malicious file in order to gain execution. User in previous analysis was targeted in a spearphishing attack and user execution is the most fitting in attack chain.

To investigate, some hypothesis need to be outlined:
- What data sources (sourcetypes) should execution of files in?
- Should we be looking for file executions before or after spearphishing attachments may have been received?
- What kind of support information is found in events when a file execution occurs?
- What other indicators do we have to start looking for user execution? (in this case we know we have an attachment called invoice.zip)
- What system did the system occur on?
- What was the user name that executed the file?
- What happened upon execution of a file?
### Splunk Analysis
Other actions relating to invoice.zip
`index=botsv2 sourcetype!=stream:smtp invoice.doc`
The following events are revealed. It reveals some command are being executed.
![](img/Pasted%20image%2020241020145859.png)
`"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\billy.tun\AppData\Local\Temp\Temp1_invoice.zip\invoice.doc" /o "u"`

The user that was responsible for the execution was btun.frothly.local at 8:28:55.000 PM on August 23rd, 2017.
We can attempt to see what is happening afterwards.
![](img/Pasted%20image%2020241020151118.png)
It seems some powershell code is being executed on the target system.
![](img/Pasted%20image%2020241020151401.png)
![](img/Pasted%20image%2020241020151340.png)
This process outline tactic T1059.001 - Command and Scripting Interpreter: Powershell and T1132.001 - Data Encoding: Standard Encoding of the MITRE ATT&CK framework.
## Conclusion
We are able to outline an attack tree of that the malicious actor Jim Smith has undergo to obtained access onto the btun system. Particularly, a spearphishing attack which contain a malicious invoice.zip document was downloaded and executed by btun, leading to execution of the invoice.doc file which contain powershell code.
### Attack tree
![](img/Pasted%20image%2020241020152108.png)
![](img/Pasted%20image%2020241020151809.png)
