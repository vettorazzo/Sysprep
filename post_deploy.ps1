if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$tipo = @("E", "N", "S")
    $tag = "*PGE*"
    $dom = "PGESL"
    $pat = "xxxxxx"
    $hostname = $env:computername
    $workgroup = $env:userdomain

    #HOSTNAME & WORKGROUP
    If ( $hostname -NotLike $tag ){
        # [E|N|S]$TAG$PAT
        Write-Output "Digite o hostname:
        N - Notebook; E - Estação; S - Servidor;
        Ex.: # [E|N|S]PGE12345"
        $nHost = Read-Host
        Rename-Computer -NewName $nHost
        Add-Computer -WorkGroupName $dom
        # -DomainCredential Domain01\Admin01 
        # reboot

    }

    # WSUS & UPDATE
    
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wsus = (Get-ItemProperty -Path $key -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    If ($wsus -ne 1){
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\WSUS\WSUS-CConfig_x64.exe -l C:\Uteis\Softwares\WSUS\WSUS-CConfig.sav -d'
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\WSUS\limpaWSUS.bat'
    }

    # KSP
    If ( -Not (Test-Path -Path "C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\klnagent.exe")){
        Write-Host "Instalando Agente Kaspersky ..."
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\Agente12.exe -s'
    }

    # VNC
    Write-Host "Instalando e configurando VNC Server ..."
    If ( -Not (Test-Path -Path "C:\Program Files\RealVNC\VNC4\winvnc4.exe")){ 
        
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\VNC\RealVNC_Enterprise.exe /SP- /VERYSILENT  /COMPONENTS=\"!vncviewer,WinVNC,WinVNC/VNCMirror,!WinVNC/VNCPrinter\" /TASKS=\"!quicklaunchicon, !desktopicon, installservice, launchservice\"'
        
        Start-Process -Wait powershell -ArgumentList 'reg.exe import /s C:\Uteis\vnc\realvnc.reg'

        Start-Process -Wait powershell -ArgumentList 'C:\Program Files\Program Files\RealVNC\VNC4\vncconfig.exe -license MZ3RP-YAYD9-VZCD9-8HQ3T-MFJUA'
        Start-Process -Wait powershell -ArgumentList 'C:\Program Files\Program Files\RealVNC\VNC4\vncconfig.exe -service -generatekeys'
        
        Write-Host "Reiniciando servido VNC4 ..."
        NET STOP WinVNC4
        NET START WinVNC4
    }

    # ZBX

    Write-Host "Reiniciando..."
    # reboot
    Shutdown /r /t 5 /f 

    # OCS
    If ( -Not (Test-Path -Path "C:\Program Files (x86)\OCS Inventory Agent\OCSInventory.exe")){
        Write-Host "Instalando OCS"
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\OCS\win7_8_10_ocspackage.exe'
    }
    
    Remove-Item -Path $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup\pre_sysprep.lnk" -Force

    Exit 0
