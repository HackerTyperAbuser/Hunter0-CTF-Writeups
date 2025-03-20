# Jarvis
```markup
Date: 2025-03-19
Platform: HackThebox
Category: Linux
Difficulty: Medium
Status: Pwned
IP: 10.10.10.143
Duration: 3 hours
Author: Nguyen Nghia Hiep
```
![](img/fd39597e558b1b53e91b9ad9dd9619a5.png)
## Introduction 
Jarvis is an straightforward labs that test technical abilities to scan a web application: identifying a SQL Injection vulnerability; privilege escalate with a command injection and vulnerable SUID binary. 
### Improved Skills:
- SQL Injection
- SUID Privilege Escalation
- SUDO Privilege Escalation
- Source code analysis
---
## Enumeration
Nmap shows ssh (22) and http port (80, 64999)
![](img/Pasted%20image%2020250320132957.png)
### Port 80 - HTTP Website
This is the website for Stark Hotel
![](img/Pasted%20image%2020250320133349.png)
Most of the link doesn't work or lead to a static website, however, there is one interesting page: Top page > "Book now!" leading to a page with URL: http://10.10.10.143/room.php?cod=1

Additionally, I from my directory brute-force I was able to find a /phpmyadmin page
![](img/Pasted%20image%2020250320143911.png)

---
## Exploitation 
### SQL Injection 
At this endpoint my first initial thought was LFI, however, this was not the case, I then attempted to test for SQLi. I notice that the endpoint takes integer values, I tested for parameterized math operations:
![Jarvis SQLi](img/Jarvis%20SQLi.gif)
This confirms the SQLi as the database process the math operations then return based on the result of the mathematical operation.
#### SQLMAP
Using SQLMap I was able to dump the database username and hash password.
![](img/Pasted%20image%2020250320143004.png)
This hash looks similar to MD5, and using CrackStation I was able to find the password to be **imissyou**
The credential will allow login to phpMyAdmin, from it can see the version 4.8.0:
![](img/Pasted%20image%2020250320144243.png)
### RCE: Public Exploit
A quick Google Search reveals public exploit: **CVE-2018-12613**
![](img/Pasted%20image%2020250320144548.png)
From it we can obtain a reverse-shell:
![](img/Pasted%20image%2020250320144852.png)
### CVE-2018-12613 - LFI: Manual Exploitation
Affects phpMyAdmin 4.8.x - < 4.8.2, the vulnerability affects the endpoint GET - /index.php?target=db_sql.php where there is a inconsistency in the '%3f' -> '?' url parameter is handled leading to a LFI.
![](img/Pasted%20image%2020250321021242.png)
We can also see the log created for our session and from it we can see that SQL queries we make are logged:
![](img/Pasted%20image%2020250321021547.png)
Attempting a Log Poisoning:
![Jarivs-LFI](img/Jarivs-LFI.gif)

---
## Post Exploitation 
### Upgrading the Shell
The first thing to make our job much more efficient is to upgrade the shell:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm (allow functionality like clear)
Ctrl + Z
stty raw -echo; fg
```
### Enumeration
I uploaded LinPEAS.sh to the victim server:
![](img/Pasted%20image%2020250320150733.png)
www-data can run /var/www/Admin-Utilities/simpler.py with pepper privileges, viewing the Python script:
![](img/Pasted%20image%2020250320151203.png)
### Privilege Escalation: Command Injection -> Pepper
The program is running OS command `ping` and there are some blacklist characters, however, this protection is not enough and there is command injection.

To evade the blacklist, we can create a reverse shell bash script then execute it:
![](img/Pasted%20image%2020250320152750.png)
### Privilege Escalation: SUID -> ROOT
From the LinPEAS result earlier, we were able to found a SUID `systemctl` for pepper account. With this we can create a malicious service:
![](img/Pasted%20image%2020250320154809.png)

Uploading the service to the victim, we can use `systemctl`:
![](img/Pasted%20image%2020250320155133.png)

---
## Trophy and Loot

1. phpMyAdmin Credentials: DBadmin : imissyou
2. user.txt: d8a8fa3db96fc2a053f92720ed46a88d
3. root.txt: 6862940a4896579889400bd4d989587c

---
## Findings
- HTTP (80) - GET - /room.php?cod=1: SQL Injection
- Weak DB hashing algorithm: MD5 algorithm 
- Vulnerable and outdated phpMyAdmin v4.8.0: Local File Inclusion -> RCE
- Vulnerable custom script (SUDO user pepper): Command Injection -> Privilege Escalation
- Vulnerable SUID permission (`systemctl`) -> Privilege Escalation
## Lesson Learnt
From Jarvis I was able to review on my Web Application testing methodology and Privilege Escalation. I could've finish this box at a much faster time as I know the vulnerability but my exploits were not working, especially for the `systemctl` SUID exploit. Moving on I hope to review the CVE-2018-12613. Credits to **0xdf** [1] for his writeup allowing to attempt the manual exploitation.
## References
[1] 0xdf. "HTB: Jarvis" (accessed 21th March 2025). 0xdf hacks stuff. [Online]. Available: https://0xdf.gitlab.io/2019/11/09/htb-jarvis.html#path-1-phpmyadmin
[2] IppSec. "HackTheBox - Jarvis" (accessed 21th March 2025). YouTube. [Online]. Available: https://www.youtube.com/watch?v=YHHWvXBfwQ8

#linux #path-traversal #boot2root #sudo #SUID #SQLi
