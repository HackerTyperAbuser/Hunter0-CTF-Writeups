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

## Introduction

Kioptrix Level 1: https://www.vulnhub.com/entry/kioptrix-level-1-1,22/
Kioptrix Level 1 is an interesting and straight forward machine that goes back to the basic, with a good methodology this box can easily be tackled.

### Improved Skills:

- Vulnerability Scanning
- Enumeration

---

## Enumeration

Pinging the entire network to discover host

```bash
fping -I <interface> -g <network> -a 2>/dev/null
```

<div align="center">
	<img src="img/Pasted%20image%2020240830192415.png">
</div>

Running the ping sweep again with Nmap, only one host was discovered

```bash
nmap -sn -PS -T4 10.0.2.1/24
```

<div align="center">
	<img src="img/Pasted%20image%2020240830192750.png">
</div>

Running a Nmap fast scan, and a full port scan we can discover services running on the target.

<div align="center">
	<img src="img/Pasted%20image%2020240830193737.png">
</div>

### Port 22 - OpenSSH

Nmap scan reveals OpenSSH and banner grabbing reveals OpenSSH version 2.9p2

<div align="center">
	<img src="img/Pasted%20image%2020240830195100.png">
</div>

This version of OpenSSH is vulnerable to some vulnerabilities such as CVE-2002-0083

<div align="center">
	<img src="img/Pasted%20image%2020240901070059.png">
</div>

### Port 80 - HTTP

<div align="center">
	<img src="img/Pasted%20image%2020240830193219.png">
</div>

Redhat Linux Host running, Apache 1.3.20, and contain information about update from RedHat Linux 6.2 and earlier that explains why the default is present

<div align="center">
	<img src="img/Pasted%20image%2020240830193513.png">
</div>

This version of Apache is vulnerable to a couple of vulnerabilities

<div align="center">
	<img src="img/Pasted%20image%2020240830194837.png">
</div>

This version of Apache seems to be vulnerable to CVE-2002-0082.

<div align="center">
	<img src="img/Pasted%20image%2020240830201122.png">
</div>

### Port 139 - Samba

Nmap scan revealed that the server has a Samba file sharing service. Enum4linux scan revealed that Samba Server contains two file IPC$ and ADMIN$ with anonymous login.

<div align="center">
	<img src="img/Pasted%20image%2020240830195523.png">
</div>

<div align="center">
	<img src="img/Pasted%20image%2020240830195456.png">
</div>

However, using smbclient and rpcclient, we were unable to access any of these shares. Using a customized bash script or Metasploit, the Samba version is revealed: Samba 2.2.1a

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

<div align="center">
	<img src="img/Pasted%20image%2020240901074211.png">
</div>

### Port 443 - HTTPS

<div align="center">
	<img src="img/Pasted%20image%2020240830201756.png">
</div>

No certificates, no information can be extracted from the secured HTTP port.

---

## Exploitation

The exploit code for Apache mod_ssl < 2.8.7 OpenSSL or OpenFuck seems interesting; reading more about the vulnerability code CVE-2002-0082, for dbm and shm session cache code in mod_ssl before 2.8.7-1.3.23 and Apache-SSL < 1.3.22+1.46, allows a buffer overflow to execute arbitrary code in the i2d_SSL_SESSION function. Here I attempt to look for information on mod_ssl.

<div align="center">
	<img src="img/Pasted%20image%2020240830202510.png">
</div>

Enables TLSv1 and SSLv3 on server.

<div align="center">
	<img src="img/Pasted%20image%2020240830202606.png">
</div>

With this information the OpenFuck exploit can be tested on the target system.

### Method 1: CVE-2002-0082

<div align="center">
	<img src="img/Pasted%20image%2020240830203641.png">
</div>

The exploit code is successful and we have gain a shell on the machine.

### Method 2: Samba CVE-2003-0201 Trans2Open

CVE-2003-0201, exploits a buffer overflow vulnerability found in Samba version 2.2.0 to 2.2.8, anonymous access to Samba is needed for this exploit. This exploit should give us root access.

<div align="center">
	<img src="img/Pasted%20image%2020240902070604.png">
</div>

---

## Post Exploitation

### Enumeration

Looking in /root/.bash_history we can find some interesting information.

<div align="center">
	<img src="img/Pasted%20image%2020240902070950.png">
</div>

Reading more about the mail command it is a utility to send mails through the command line.

<div align="center">
	<img src="img/Pasted%20image%2020240902071712.png">
</div>

We have pwned this machine!

---

## Trophy and Loot

Pwned the Kioptrix Level 1 system and reading the hidden mail.

---

## Findings

- The default RedHat 'It Works!' page (misconfiguration)
- Version of Apache, OpenSSH and Samba is revealed.
- Vulnerable to CVE-2002-0082, CVE-2002-0083, CVE-2003-0201

## Lesson Learnt

### Explore all the vulnerabilities

This box improves my overall methodology, a machine can have more than one vulnerability and this was something I ignored. When discovered the Apache vulnerability I instantly attempted to exploit it and ignored a serious Samba vulnerability which would give privileged access. Furthermore, I didn't research the vulnerability properly, leading to the Apache exploit not giving root user. Kioptrix Level 1 was simple and improved my enumeration and vulnerability scanning methodology.
