```markup
Alias: Kioptrix Level 1
Date: 2024-08-30
Platform: VulnHub 
Category: Linux
Difficulty: Easy
IP: 10.0.2.5
Duration: 1h30m
Author Nguyen Nghia Hiep
```

## Table of Contents
---
## Introduction 
text text text 
### Improved Skills:
- Vulnerability Scanning
- Enumeration
---
## Enumeration
Pinging the entire network to discover host
```bash
fping -I <interface> -g <network> -a 2>/dev/null
```
![[Pasted image 20240830192415.png]]
Running the ping sweep again with Nmap, only one host was discovered
```bash
nmap -sn -PS -T4 10.0.2.1/24
```
![[Pasted image 20240830192750.png]]
Running a Nmap fast scan, and a full port scan we can discover services running on the target.
![[Pasted image 20240830193737.png]]
### Port 22 - OpenSSH
Nmap scan reveals OpenSSH and banner grabbing reveals OpenSSH version 2.9p2
![[Pasted image 20240830195100.png]]
This version of OpenSSH is vulnerable to some vulnerabilities such as CVE-2002-0083![[Pasted image 20240901070059.png]]
### Port 80 - HTTP 
![[Pasted image 20240830193219.png]]
Redhat Linux Host running, Apache 1.3.20, and contain information about update from RedHat Linux 6.2 and earlier that explains why the default is present
![[Pasted image 20240830193513.png]]
This version of Apache is vulnerable to a couple of vulnerabilities
![[Pasted image 20240830194837.png]]
This version of Apache seems to be vulnerable to CVE-2002-0082.
![[Pasted image 20240830201122.png]]
### Port 139 - Samba
Nmap scan revealed that the server has a Samba file sharing service. Enum4linux scan revealed that Samba Server contains two file IPC$ and ADMIN$ with anonymous login.
![[Pasted image 20240830195523.png]]
![[Pasted image 20240830195456.png]]
However, using smbclient and rpcclient, we were unable to access any of these shares. Using a customized bash script or Metasploit, the Samba version is revealed:  Samba 2.2.1a
```bash
#!/bin/bash

if [ -z $1 -o -z $2 ]; then 
        echo "Usage: ./smbver.sh RHOST INTERFACE {RPORT}" && exit; 
else 
        rhost=$1;
        int=$2;
fi

if [ ! -z $3 ]; then 
        rport=$3; 
else 
        rport=139; 
fi

tcpdump -s0 -n -i $int src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m"
```
This version of Samba is vulnerable to CVE-2003-0201 (Trans2open).
![[Pasted image 20240901074211.png]]
### Port 443 - HTTPS
![[Pasted image 20240830201756.png]]
No certificates, no information can be extracted from the secured HTTP port.

---
## Exploitation 
The exploit code for Apache mod_ssl < 2.8.7 OpenSSL or OpenFuck seems interesting; reading more about the vulnerability code CVE-2002-0082, for dbm and shm session cache code in mod_ssl before 2.8.7-1.3.23 and Apache-SSL < 1.3.22+1.46, allows a buffer overflow to execute arbitrary code in the i2d_SSL_SESSION function. Here I attempt to look for information on mod_ssl.
![[Pasted image 20240830202510.png]]
Enables TLSv1 and SSLv3 on server.
![[Pasted image 20240830202606.png]]
With this information the OpenFuck exploit can be tested on the target system. 
### Method 1: CVE-2002-0082
![[Pasted image 20240830203641.png]]
The exploit code is successful and we have gain a shell on the machine. 
### Method 2: Samba CVE-2003-0201 Trans2Open
CVE-2003-0201, exploits a buffer overflow vulnerability found in Samba version 2.2.0 to 2.2.8, anonymous access to Samba is needed for this exploit. This exploit should give us root access.
![[Pasted image 20240902070604.png]]
---
## Post Exploitation 
### Enumeration
Looking in /root/.bash_history we can find some interesting information.
![[Pasted image 20240902070950.png]]
Reading more about the mail command it is a utility to send mails through the command line.
![[Pasted image 20240902071712.png]]
We have pwned this machine!

---
## Trophy and Loot
Pwned the Kioptrix Level 1 system and reading the hidden mail.

---
## Findings
- Findings 1
- Findings 2
## Lesson Learnt
