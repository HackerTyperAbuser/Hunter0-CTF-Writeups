# Chatterbox
```markup
Date: 2024-10-14
Platform: HackTheBox
Category: Windows
Difficulty: Medium
Status: Pwned
IP: 10.10.10.74
Duration: 2hrs 13 minutes
Author: Nguyen Nghia Hiep
```
![](img/Pasted%20image%2020241014224331.png)
## Introduction 
Chatterbox is a simple box that looks into a vulnerability within AChat and test the post-enumeration skills on Windows system to escalate privileges via credentials in the Autologon service. 
### Improved Skills:
- Post Exploitation Enumeration.
- Usage of different command to obtain Windows shell.
- Windows ACLs
### Used Tools :
- Metasploit Framework
- Nmap
- Smbclient
- Wmiexec
- Psexec
- WinPEAS
- curl
---
## Enumeration
Nmap scan results, 139/445 SMB and novice 9255 and 9256 port are interesting target for enumeration.
![](img/Pasted%20image%2020241014234107.png)
### Port 445 - SMB
Nmap scan revealed the Operating System information
- OS: Windows 7 Professional 7601 Service Pack 1 (6.1)
- Computer name: Chatterbox
Beside this anonymous authentication was not allowed and we cannot connect to SMB shares (NT_STATUS_ACCESS_DENIED).
### Port 9255/9256 - AChat
Port 9255 reveals HTTP, however, there were no web page when visiting address on the browser, but we can curl the address.
![](img/Pasted%20image%2020241015163629.png)

Port 9256, displays AChat service, there were no more information from this.
- AChat server
---
## Vulnerability Analysis
Information gathered:
- AChat server
- Windows 7 Professional 7601 Service Pack 1 (6.1)
There is not much information from enumeration, I decided to look at port 9256 information to understand more about AChat service which reveals a security vulnerability.
![](img/Pasted%20image%2020241015164633.png)
Google searched revealed PoC for the vulnerability.
![](img/Pasted%20image%2020241015164936.png)

---
## Exploitation 
### Manual
There seems to be a Buffer Overflow vulnerability when sending a crafted UDP packet to default port 9256.
Fixing exploit: 
- Using our own payload
![](img/Pasted%20image%2020241015165926.png)
- Replacing the PoC with our payload.
- Start listener, execute PoC and retrieve reverse shell.
![](img/Pasted%20image%2020241015170554.png)
### Metasploit
Exploitation through Metasploit module: exploit/windows/misc/achat_bof
Set options rhosts, lhosts, lport and payload.
![](img/Pasted%20image%2020241015171304.png)
Execute the exploit and obtain a shell. 
- Note: all encoder fails -> no shell :( Here changing payloads, and running the exploit few times.
- If no luck -> use manual exploit to Metasploit multi-handler.
![](img/Pasted%20image%2020241015172119.png)
Here if we want meterpreter shell we can upload and execute it to another multi-handler.

---
## Post Exploitation 
### Enumeration
The obtained user is CHATTERBOX\\Alfred which allows us to retrieve user.txt
![](img/Pasted%20image%2020241015173617.png)
Alfred is not part of the local administrator group, so we have to escalate our privileges.
![](img/Pasted%20image%2020241015173756.png)
Uploading WinPEAS onto the target; running it reveals some interesting information.
![](img/Pasted%20image%2020241015180038.png)
- Credentials Alfred:Welcome1!
- Alfred seems to have permission into the Administrator directory?
### Privilege Escalation
### Method 1: Password Spraying, Credential PrivEsc
With only two users Alfred and Administrator, the password was used to spray to see if passwords are repeated.
![](img/Pasted%20image%2020241015190518.png)
Administrator user was also using the same password and we can log in as administrator.
![](img/Pasted%20image%2020241015192300.png)
Root.txt file could be retrieved and machine in PWNED!
### Method 2: Changing root.txt ACLs
In my initial attempt to retrieve root.txt I logged in using psexec and obtain NT_AUTHORITY\\SYSTEM, however, to my surprised I did not have permission to open root.txt.
![](img/Pasted%20image%2020241015192926.png)
This was surprising because NT_AUTHORITY\\SYSTEM the highest privileged user. Earlier in our enumeration, Alfred user was somehow able to have all access into the administrator directory.

Logging in as Alfred.
- Here it seems that Alfred is the owner of root.txt
However, the root flag cannot be retrieved, because we don't have permission to read it.
![](img/Pasted%20image%2020241015200912.png)
because Alfred is the owner of the file, we can add permission to Alfred to read the file root.txt.
![](img/Pasted%20image%2020241015201402.png)

---
## Trophy and Loot
1. user.txt
2. root.txt
3. Credentials:
	- Alfred:Welcome1!
	- Administrator:Welcome1!

---
## Findings
- Vulnerable AChat service on port 9256 which allows for command execution. Available PoC.
- Weak and reuse of credentials for Administrator account.
- SMB allows for OS enumeration which reveal Windows 7 machine.
## Lesson Learnt
### Checking for ACLs of CTF files
The root.txt really stumped me when I first gained NT_AUTHORITY\\SYSTEM, eventually from this box I was able to learn about Access Control List (ACLs) on files and directories. Learning about how owners can change permissions on the file they own on Windows machine. Understanding this capability I can add it own methodology for CTFs or when needing to read a file on a system. 
### Building your own Username.txt and Password.txt
Brute force attacks are one of my weakness not because they are hard, but because they require some thinking outside the box and mindset of an average user. A successful brute force attack depends a great wordlist, from this box I was able to learn that users are constantly re-using their credentials, so always add them in your wordlists! You never know how far these credentials can take you.

#credentials-privesc #windows #boot2root #ACLs
