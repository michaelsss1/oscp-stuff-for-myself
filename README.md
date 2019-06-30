# for-oscp
some notes ,scripts
# 本地编译exp 如果目标机器没有gcc
gcc -m32 -Wl,--hash-style=both -o suid suid.c
# accesschk.exe usage

accesschk.exe -uwcqv "Users" * /accepteula
accesschk.exe -ucqv [service_name] 
