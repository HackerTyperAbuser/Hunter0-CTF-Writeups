# Arctic
```markup
Date: 2024-10-17
Platform: HackTheBox
Category: Windows
Difficulty: Easy
Status: Pwned
IP: 10.10.10.11
Duration: 54 minutes
Author: Nguyen Nghia Hiep
```
![](img/Pasted%20image%2020241017221434.png)
## Introduction 
Arctic is an easy machine that has a vulnerable version of Adobe ColdFusion and a straight-forward privilege escalation vector. However, it really shines as a machine for testing different tools and methodologies.
### Improved Skills:
- Windows Kernel Privilege Escalation
- Vulnerability scanning and fixing exploit code
- Testing with various tools to own the system
### Used Tools :
- Nmap
- Crackstation
- Metasploit
- Windows Exploit Suggester
---
## Enumeration
Nmap scan results, novice port 8500 was discovered on the target.
![](img/Pasted%20image%2020241017204859.png)
### Port 8500 
Checking this port on the browser, a website containing various contents is revealed. 
![](img/Pasted%20image%2020241017205911.png)

CFIDE and cfdocs directories was interesting, a quick Google search revealed the target infrastructure.
- Adobe ColdFusion 
There also an administrator panel (/CFIDE/administrator)
![](img/Pasted%20image%2020241017210242.png)
![](img/Pasted%20image%2020241017210636.png)
- Adobe ColdFusion 8 Administrator
---
## Vulnerability Analysis
Adobe ColdFusion 8 Administrator seems to have some serious vulnerabilities.
![](img/Pasted%20image%2020241017211800.png)

---
## Exploitation 
### Path Traversal 
There is a path traversal vulnerability that allows retrieval of admin user hash.
![](img/Pasted%20image%2020241018122924.png)
![](img/Pasted%20image%2020241018123000.png)
Obtained credential:
- admin:happyday
### File Upload -> RCE
Using the publicly available File Upload -> RCE exploit code. This is an unauthenticated file upload vulnerability that allows for remote code execution.
![](img/Pasted%20image%2020241017221352.png)
![](img/Pasted%20image%2020241017221030.png)

We have gained foothold onto the system.

---
## Post Exploitation 
### Enumeration
When on a Windows box, I always start by running the systeminfo command. 
![](img/Pasted%20image%2020241017223743.png)
![](img/Pasted%20image%2020241017223914.png)
Information found:
- Microsoft Windows Server 2008 R2 Standard (old system)
- OS Version: 6.1.7600 N/A Build 7600
- No Hotfix for this version.
Old version of Windows and no hotfix typically means Kernel Exploits.
### Privilege Escalation - Kernel Exploits
Following from manual enumeration we can attempt to find some Kernel Exploits. Here I used Windows Exploit Suggester to find kernel vulnerabilities.
![](img/Pasted%20image%2020241018120213.png)
I attempted some of the Kernel exploit PoC, however, it seems that the system was blocking some command execution until I tried MS10-059 exploit, which I was able to obtain NT_AUTHORITY\\SYSTEM.
![](img/Pasted%20image%2020241018120358.png)
![](img/Pasted%20image%2020241018120419.png)
### Metasploit 
For some reason, I can't seem to get the exploit working in Metasploit trying to gain foothold. We can use the manual exploit to get the initial foothold then upload a meterpreter binary on the system.
![](img/Pasted%20image%2020241018121614.png)
![](img/Pasted%20image%2020241018121648.png)
Starting a listener and obtain meterpreter shell. 
![](img/Pasted%20image%2020241018121830.png)
NOTE: You should always migrate to x64 processes for more stable shell.
![](img/Pasted%20image%2020241018122534.png)

After getting the session, find kernel exploit /post/multi/recon/local_exploit_suggester
![](img/Pasted%20image%2020241018122117.png)
Privilege escalation with Metasploit module
![](img/Pasted%20image%2020241018122643.png)

---
## Trophy and Loot

1. user.txt
2. root.txt
3. Adobe ColdFusion 8 Administrator Credential
	- admin:happyday

---
## Findings
- Vulnerable software Adobe ColdFusion 8 Administrator which was vulnerable to a dangerous Path Traversal and File Upload vulnerability leading to exploitation. PoCs are publicly available. 
- System is ancient and was not patched leading to multiple privilege escalation vulnerabilities.
- Admin credentials are rather weak, can be brute-force.
- Adobe ColdFusion 8 is running under a valid user account and not as a service account.
## Lesson Learnt
### Fixing exploits and Kernel vulnerabilities enumeration
Honestly Arctic is a simple box, with a simple privilege escalation and foothold, however, it from this simple box I was able to consolidate my methodology. Attacking Arctic I was able to learn a few things, one reading the exploit code and figuring out what the code is doing, second using various tools to enumerate the system (in particular Window exploit suggester to find kernel exploits). Kernel exploits can lead to quick wins, however, they must be test thoroughly as it may results in system crashes. 

#kernel-privesc #windows #boot2root 
