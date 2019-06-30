#!/usr/env python

###############################################################################################################
## [Title]: linuxprivchecker.py -- a Linux Privilege Escalation Check Script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed locally on a Linux box to enumerate basic system info and 
## search for common privilege escalation vectors such as world writable files, misconfigurations, clear-text
## passwords and applicable exploits. 
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I have no plans to maintain updates, 
## I did not write it to be efficient and in some cases you may find the functions may not produce the desired 
## results.  For example, the function that links packages to running processes is based on keywords and will 
## not always be accurate.  Also, the exploit list included in this function will need to be updated over time. 
## Feel free to change or improve it any way you see fit.
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
###############################################################################################################

# conditional import for older versions of python not compatible with subprocess
try:
    import subprocess as sub
    compatmode = 0 # newer version of python, no need for compatibility mode
except ImportError:
    import os # older version of python, need to use os instead
    compatmode = 1

# title / formatting
bigline = "================================================================================================="
smlline = "-------------------------------------------------------------------------------------------------"

print bigline 
print "LINUX PRIVILEGE ESCALATION CHECKER"
print bigline
print

# loop through dictionary, execute the commands, store the results, return updated dict
def execCmd(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
	if compatmode == 0: # newer version of python, use preferred subprocess
            out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
            results = out.split('\n')
	else: # older version of python, use os.popen
	    echo_stdout = os.popen(cmd, 'r')  
            results = echo_stdout.read().split('\n')
        cmdDict[item]["results"]=results
    return cmdDict

# print results for each previously executed command, no return value
def printResults(cmdDict):
    for item in cmdDict:
	msg = cmdDict[item]["msg"]
	results = cmdDict[item]["results"]
        print "[+] " + msg
        for result in results:
	    if result.strip() != "":
	        print "    " + result.strip()
	print
    return

def writeResults(msg, results):
    f = open("privcheckout.txt", "a");
    f.write("[+] " + str(len(results)-1) + " " + msg)
    for result in results:
        if result.strip() != "":
            f.write("    " + result.strip())
    f.close()
    return

# Basic system info
print "[*] GETTING BASIC SYSTEM INFO...\n"

results=[]

sysInfo = {"OS":{"cmd":"cat /etc/issue","msg":"Operating System","results":results}, 
	   "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results}, 
	   "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results}
	  }

sysInfo = execCmd(sysInfo)
printResults(sysInfo)

# Networking Info

print "[*] GETTING NETWORKING INFO...\n"

netInfo = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results},
	   "ROUTE":{"cmd":"route", "msg":"Route", "results":results},
	   "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results}
	  }

netInfo = execCmd(netInfo)
printResults(netInfo)

# File System Info
print "[*] GETTING FILESYSTEM INFO...\n"

driveInfo = {"MOUNT":{"cmd":"mount","msg":"Mount results", "results":results},
	     "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results}
	    }

driveInfo = execCmd(driveInfo)
printResults(driveInfo)

# Scheduled Cron Jobs
cronInfo = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Scheduled cron jobs", "results":results},
	    "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs", "results":results}
	   }

cronInfo = execCmd(cronInfo)
printResults(cronInfo)

# User Info
print "\n[*] ENUMERATING USER AND ENVIRONMENTAL INFO...\n"

userInfo = {"WHOAMI":{"cmd":"whoami", "msg":"Current User", "results":results},
	    "ID":{"cmd":"id","msg":"Current User ID", "results":results},
	    "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"All users", "results":results},
	    "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:", "results":results},
	    "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)", "results":results},
	    "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment", "results":results},
	    "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results},
	    "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity", "results":results}
	   }

userInfo = execCmd(userInfo)
printResults(userInfo)

if "root" in userInfo["ID"]["results"][0]:
    print "[!] ARE YOU SURE YOU'RE NOT ROOT ALREADY?\n"

# File/Directory Privs
print "[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...\n"

fdPerms = {"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'", "results":results},
	   "WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories for Users other than Root", "results":results},
	   "WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files", "results":results},
	   "SUID":{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Files and Directories", "results":results},
	   "ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Checking if root's home folder is accessible", "results":results}
	  }

fdPerms = execCmd(fdPerms) 
printResults(fdPerms)

pwdFiles = {"LOGPWDS":{"cmd":"find /var/log -name '*.log' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Logs containing keyword 'password'", "results":results},
	    "CONFPWDS":{"cmd":"find /etc -name '*.c*' 2>/dev/null | xargs -l10 egrep 'pwd|password' 2>/dev/null", "msg":"Config files containing keyword 'password'", "results":results},
	    "SHADOW":{"cmd":"cat /etc/shadow 2>/dev/null", "msg":"Shadow File (Privileged)", "results":results}
	   }

pwdFiles = execCmd(pwdFiles)
printResults(pwdFiles)

# Processes and Applications
print "[*] ENUMERATING PROCESSES AND APPLICATIONS...\n"

if "debian" in sysInfo["KERNEL"]["results"][0] or "ubuntu" in sysInfo["KERNEL"]["results"][0]:
    getPkgs = "dpkg -l | awk '{$1=$4=\"\"; print $0}'" # debian
else:
    getPkgs = "rpm -qa | sort -u" # RH/other

getAppProc = {"PROCS":{"cmd":"ps aux | awk '{print $1,$2,$9,$10,$11}'", "msg":"C"val":"kernel"}},
		"2.4.22 "'do_brk()'" local Root Exploit (PoC)":{"minver":"2.4.22", "maxver":"2.4.22", "exploitdb":"129", "lang":"asm", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"<= 2.4.22 (do_brk) Local Root Exploit (working)":{"minver":"0", "maxver":"2.4.22", "exploitdb":"131", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4.x mremap() bound checking Root Exploit":{"minver":"2.4", "maxver":"2.4.99", "exploitdb":"145", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"<= 2.4.29-rc2 uselib() Privilege Elevation":{"minver":"0", "maxver":"2.4.29", "exploitdb":"744", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4 uselib() Privilege Elevation Exploit":{"minver":"2.4", "maxver":"2.4", "exploitdb":"778", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4.x / 2.6.x uselib() Local Privilege Escalation Exploit":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"895", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4/2.6 bluez Local Root Privilege Escalation Exploit (update)":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"926", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"bluez"}},
		"<= 2.6.11 (CPL 0) Local Root Exploit (k-rad3.c)":{"minver":"0", "maxver":"2.6.11", "exploitdb":"1397", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"MySQL 4.x/5.0 User-Defined Function Local Privilege Escalation Exploit":{"minver":"0", "maxver":"99", "exploitdb":"1518", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"mysql"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2004", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (2)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2005", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (3)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2006", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6.13 <= 2.6.17.4 sys_prctl() Local Root Exploit (4)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2011", "lang":"sh", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"<= 2.6.17.4 (proc) Local Root Exploit":{"minver":"0", "maxver":"2.6.17.4", "exploitdb":"2013", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6.13 <= 2.6.17.4 prctl() Local Root Exploit (logrotate)":{"minver":"2.6.13", "maxver":"2.6.17.4", "exploitdb":"2031", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"Ubuntu/Debian Apache 1.3.33/1.3.34 (CGI TTY) Local Root Exploit":{"minver":"4.10", "maxver":"7.04", "exploitdb":"3384", "lang":"c", "keywords":{"loc":["os"], "val":"debian"}},
		"Linux/Kernel 2.4/2.6 x86-64 System Call Emulation Exploit":{"minver":"2.4", "maxver":"2.6", "exploitdb":"4460", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"< 2.6.11.5 BLUETOOTH Stack Local Root Exploit":{"minver":"0", "maxver":"2.6.11.5", "exploitdb":"4756", "lang":"c", "keywords":{"loc":["proc","pkg"], "val":"bluetooth"}},
		"2.6.17 - 2.6.24.1 vmsplice Local Root Exploit":{"minver":"2.6.17", "maxver":"2.6.24.1", "exploitdb":"5092", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6.23 - 2.6.24 vmsplice Local Root Exploit":{"minver":"2.6.23", "maxver":"2.6.24", "exploitdb":"5093", "lang":"c", "keywords":{"loc":["os"], "val":"debian"}},
		"Debian OpenSSL Predictable PRNG Bruteforce SSH Exploit":{"minver":"0", "maxver":"99", "exploitdb":"5720", "lang":"python", "keywords":{"loc":["os"], "val":"debian"}},
		"Linux Kernel < 2.6.22 ftruncate()/open() Local Exploit":{"minver":"0", "maxver":"2.6.22", "exploitdb":"6851", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"< 2.6.29 exit_notify() Local Privilege Escalation Exploit":{"minver":"0", "maxver":"2.6.29", "exploitdb":"8369", "lang"ocal Ring0 Root Exploit":{"minver":"2", "maxver":"2.99", "exploitdb":"9435", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.x sock_sendpage() Local Root Exploit 2":{"minver":"2", "maxver":"2.99", "exploitdb":"9436", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4/2.6 sock_sendpage() ring0 Root Exploit (simple ver)":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9479", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6 < 2.6.19 (32bit) ip_append_data() ring0 Root Exploit":{"minver":"2.6", "maxver":"2.6.19", "exploitdb":"9542", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4/2.6 sock_sendpage() Local Root Exploit (ppc)":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9545", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"< 2.6.19 udp_sendmsg Local Root Exploit (x86/x64)":{"minver":"0", "maxver":"2.6.19", "exploitdb":"9574", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"< 2.6.19 udp_sendmsg Local Root Exploit":{"minver":"0", "maxver":"2.6.19", "exploitdb":"9575", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4/2.6 sock_sendpage() Local Root Exploit [2]":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9598", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4/2.6 sock_sendpage() Local Root Exploit [3]":{"minver":"2.4", "maxver":"2.6.99", "exploitdb":"9641", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.4.1-2.4.37 and 2.6.1-2.6.32-rc5 Pipe.c Privelege Escalation":{"minver":"2.4.1", "maxver":"2.6.32", "exploitdb":"9844", "lang":"python", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"'pipe.c' Local Privilege Escalation Vulnerability":{"minver":"2.4.1", "maxver":"2.6.32", "exploitdb":"10018", "lang":"sh", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"2.6.18-20 2009 Local Root Exploit":{"minver":"2.6.18", "maxver":"2.6.20", "exploitdb":"10613", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"Apache Spamassassin Milter Plugin Remote Root Command Execution":{"minver":"0", "maxver":"99", "exploitdb":"11662", "lang":"sh", "keywords":{"loc":["proc"], "val":"spamass-milter"}},
		"<= 2.6.34-rc3 ReiserFS xattr Privilege Escalation":{"minver":"0", "maxver":"2.6.34", "exploitdb":"12130", "lang":"python", "keywords":{"loc":["mnt"], "val":"reiser"}},
		"Ubuntu PAM MOTD local root":{"minver":"7", "maxver":"10.04", "exploitdb":"14339", "lang":"sh", "keywords":{"loc":["os"], "val":"ubuntu"}},
		"< 2.6.36-rc1 CAN BCM Privilege Escalation Exploit":{"minver":"0", "maxver":"2.6.36", "exploitdb":"14814", "lang":"c", "keywords":{"loc":["kernel"], "val":"kernel"}},
		"Kernel ia32syscall Emulation Privilege Escalation":{"minver":"0", "maxver":"99", "exploitdb":"15023", "lang":"c", "keywords":{"loc":
	    elif loc == "os":
		if (keyword in os) or (keyword in kernel):
		    highprob.append(sploitout) # if sploit is specifically applicable to this OS consider it a higher probability/applicability
		    break  
	    elif loc == "mnt":
		if keyword in mount:
		    highprob.append(sploitout) # if sploit is specifically applicable to a mounted file system consider it a higher probability/applicability
		    break
	    else:
		avgprob.append(sploitout) # otherwise, consider average probability/applicability based only on kernel version

print "    Note: Exploits relying on a compile/scripting language not detected on this system are marked with a '**' but should still be tested!"
print

print "    The following exploits are ranked higher in probability of success because this script detected a related running process, OS, or mounted file system" 
for exploit in highprob:
    print "    - " + exploit
print

print "    The following exploits are applicable to this kernel version and should be investigated as well"
for exploit in avgprob:
    print "    - " + exploit

print 	
print "Finished"
print bigline

