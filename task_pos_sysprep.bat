@echo off
schtasks /create /sc onlogon /tn "task_pos_sysprep" /ru SYSTEM  /tr "C:\Uteis\pos_sysprep.bat" /rl HIGHEST