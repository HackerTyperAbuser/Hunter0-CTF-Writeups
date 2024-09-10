```markup
Alias: Kioptrix 1.1
Date: 2024-09-09
Platform: VulnHub
Category: Linux
Difficulty: Easy
IP: 10.0.2.15
Duration: 1h45m
Author Nguyen Nghia Hiep
```
## Introduction 
Kioptrix Level 1.1: https://www.vulnhub.com/entry/kioptrix-level-11-2,23/
Kioptrix Level 1.1 is an interesting and straight forward machine, with a good methodology this box can easily be tackled.
### Improved Skills:
- Enumeration
- Privilege Escalation
---
## Enumeration
Nmap scan results
![[Pasted image 20240909232823.png]]
![[Pasted image 20240909232844.png]]
### Port 22 - SSH
Discover that OpenSSH 3.9p1 which is not vulnerable to anything.
### Port 80/443 - HTTP/S
Discover Apache  httpd 2.0.52  (CentOS)
![[Pasted image 20240909233019.png]]
The webpage contains a login, some simple credentials were test, however, didn't return much result. No hidden directories were found.
Knowing that the webpage utilizes a MySQL database, some SQLi was tested.
![[Pasted image 20240909234627.png]]
SQLi is detected using SQLMap and allowed bypass of authentication. The webpage allows user to ping to a particular host.
![[Pasted image 20240909233851.png]]
Results is returned in pingit.php
![[Pasted image 20240909234010.png]]
### Port 111 - RPC
Did reveal other program, running on the target, reveals some UDP open ports. Particularly the program at TCP 864 is also ran on 860 UDP.
### Port 643 - IPP CUPS 1.1
Didn't reveal much information, connection refused.
### Port 3306 - MySQL
Had some access control, connection was refused, so not much can be extracted besides that the database is MySQL.
![[Pasted image 20240909233735.png]]

---
## Exploitation 
### Command Injection
Earlier we discovered that the web page contains a pinging functionality, the result returned in pingit.php seems as if a ping command is being run on the backend of the web page then rendered back.
Test for command injection with some simple payloads. We were able to add flags of the Ping commands and execute it.
![[Pasted image 20240909235020.png]]
Commands can be executed. Payload = ;whoami;
![[Pasted image 20240910000520.png]]
With this we can attempt to run a reverse shell and gain foothold to this system.
![[Pasted image 20240910000641.png]]
We can see that indeed the pingit.php file was executing the `ping` command
![[Pasted image 20240910000935.png]]

---
## Post Exploitation
### Enumeration
The web page must connect to the MySQL database to process the authentication, the index.php file was checked. 
![[Pasted image 20240910004812.png]]
Here we found the credentials john:hiroshima which was used to log into the local MySQL server because we weren't able to connect to it from our attack machine.
![[Pasted image 20240910005850.png]]
The password are not hashed but are in cleartext, using these credentials we can log into the web page.
### Privilege Escalation: Kernel Exploits
The credential weren't useful to us since we can't use Sudo, SSH or change users. Using LinEnum, we discovered that the Kernel version for this system is relatively old, 2.6.9-55.EL CentOS release 4.5 (final). Beside this there was an interesting binary `gcc`
![[Pasted image 20240910001305.png]]
This version of the kernel is vulnerable to CVE-2009-2698, local privilege escalation exploit.
![[Pasted image 20240910001402.png]]
This exploit was uploaded, compiled on the target machine and executed
```bash
gcc exploit.c -o cve-2009-2698 && ./cve-2009-2698
```
![[Pasted image 20240910001713.png]]
We have successfully escalated our privileges and pwned this machine.

---
## Trophy and Loot
Pwned the Kioptrix Level 1.1 system and steal MySQL credentials on system.

---
## Findings
- SQL Injection vulnerability on webpage.
- Command Injection vulnerability on webpage.
- Old system and contains a Kernel vulnerability.
- MySQL credentials were obtained and allowed for exfiltration of database information.
## Lesson Learnt
### Using Tools Effectively
In my run of the Kioptrix 1.1 box, I really struggled with the initial enumeration. This is because earlier I have crossed out SQLi from my checklist. I only attempted one or two manual payload and used SQLMap wrongly (didn't enable risk 3, so no OR payloads were tested) then instantly crossed out SQLi. Lesson here is to know the full functionality of your tool, web application testing is a weakness I have because I am lazy but be sure to test some manual payloads before using automated tools.
### Always check for Kernel Exploits
Although it was written in my methodology, I completely forgot about Kernel exploits, they are rare and may lead to system crashes and I just kept looking and looking for other Privilege Escalation vectors. Always remember Kernel exploits as they can lead to quick wins, especially for older systems.

#enumeration #privesc #boot2root #linux