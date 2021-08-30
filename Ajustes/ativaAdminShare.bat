@echo off
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\lanmanserver\parameters" /v AutoShareWks /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\lanmanserver\parameters" /v AutoShareServer /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow

netsh advfirewall firewall set rule group="Compartilhamento de Arquivo e Impressora" new enable=Yes
netsh advfirewall firewall set rule group="Descoberta de Rede" new enable=Yes

net stop browser
net stop server

net start browser
net start server
