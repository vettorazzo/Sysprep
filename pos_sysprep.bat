@echo off
cmd /c "powershell.exe -Command {Unblock-File C:\Uteis\pre_sysprep.ps1}"
cmd /c "powershell.exe -Command C:\Uteis\pre_sysprep.ps1"