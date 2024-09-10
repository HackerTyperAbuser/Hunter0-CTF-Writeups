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

<div align="center">
	<img src="img/Pasted%20image%2020240909232823.png">
</div>


<div align="center">
	<img src="img/Pasted%20image%2020240909232844.png">
</div>

### Port 22 - SSH
Discover that OpenSSH 3.9p1 which is not vulnerable to anything.
### Port 80/443 - HTTP/S
Discover Apache  httpd 2.0.52  (CentOS)

<div align="center">
	<img src="img/Pasted%20image%2020240909233019.png">
</div>

The webpage contains a login, some simple credentials were test, however, didn't return much result. No hidden directories were found.
Knowing that the webpage utilizes a MySQL database, some SQLi was tested.

<div align="center">
	<img src="img/Pasted%20image%2020240909234627.png">
</div>

SQLi is detected using SQLMap and allowed bypass of authentication. The webpage allows user to ping to a particular host.

<div align="center">
	<img src="img/Pasted%20image%2020240909233851.png">
</div>

Results is returned in pingit.php

<div align="center">
	<img src="img/Pasted%20image%2020240909234010.png">
</div>

### Port 111 - RPC
Did reveal other program, running on the target, reveals some UDP open ports. Particularly the program at TCP 864 is also ran on 860 UDP.
### Port 643 - IPP CUPS 1.1
Didn't reveal much information, connection refused.
### Port 3306 - MySQL
Had some access control, connection was refused, so not much can be extracted besides that the database is MySQL.

<div align="center">
	<img src="img/Pasted%20image%2020240909233735.png">
</div>


---
## Exploitation 
### Command Injection
Earlier we discovered that the web page contains a pinging functionality, the result returned in pingit.php seems as if a ping command is being run on the backend of the web page then rendered back.
Test for command injection with some simple payloads. We were able to add flags of the Ping commands and execute it.

<div align="center">
	<img src="img/Pasted%20image%2020240909235020.png">
</div>

Commands can be executed. Payload = ;whoami;

<div align="center">
	<img src="img/Pasted%20image%2020240910000520.png">
</div>

With this we can attempt to run a reverse shell and gain foothold to this system.

<div align="center">
	<img src="img/Pasted%20image%2020240910000641.png">
</div>

We can see that indeed the pingit.php file was executing the `ping` command

<div align="center">
	<img src="img/Pasted%20image%2020240910000935.png">
</div>


---
## Post Exploitation
### Enumeration
The web page must connect to the MySQL database to process the authentication, the index.php file was checked. 

<div align="center">
	<img src="img/Pasted%20image%2020240910004812.png">
</div>

Here we found the credentials john:hiroshima which was used to log into the local MySQL server because we weren't able to connect to it from our attack machine.

<div align="center">
	<img src="img/Pasted%20image%2020240910005850.png">
</div>

The password are not hashed but are in cleartext, using these credentials we can log into the web page.
### Privilege Escalation: Kernel Exploits
The credential weren't useful to us since we can't use Sudo, SSH or change users. Using LinEnum, we discovered that the Kernel version for this system is relatively old, 2.6.9-55.EL CentOS release 4.5 (final). Beside this there was an interesting binary `gcc`

<div align="center">
	<img src="img/Pasted%20image%2020240910001305.png">
</div>

This version of the kernel is vulnerable to CVE-2009-2698, local privilege escalation exploit.

<div align="center">
	<img src="img/Pasted%20image%2020240910001402.png">
</div>

This exploit was uploaded, compiled on the target machine and executed
```bash
gcc exploit.c -o cve-2009-2698 && ./cve-2009-2698
```

<div align="center">
	<img src="img/Pasted%20image%2020240910001713.png">
</div>

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