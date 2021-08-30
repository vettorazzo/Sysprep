if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'
function Start-Anim {

    param (
        $num = 1
    )

    $animation = @"
#
|
#
/
#
-
#
\
"@
    $frames = $animation.Split("#").Trim()
    $animationLoopNumber = $num # number of times to loop animation
    $animationSpeed = 50 # time in milliseconds to show each frame
    $i = 0
    Do {
        Foreach ($frame in $frames) {
            Write-Host "`r$frame" -NoNewline
            Start-Sleep -Milliseconds $animationSpeed
        }
        $i++
    } Until ($i -eq $animationLoopNumber)
    Write-Host "`r " -NoNewline
    Write-Host ""
}
function Show-Banner {

    # Clear-Host

    Write-Host "       _____           _____                   _____           _       _      "
    Write-Host "      / ____|         |  __ \                 / ____|         (_)     | |     "
    Write-Host "     | (___  _   _ ___| |__) | __ ___ _ __   | (___   ___ _ __ _ _ __ | |_    "
    Write-Host "      \___ \| | | / __|  ___/ '__/ _ \ '_ \   \___ \ / __| '__| | '_ \| __|   "
    Write-Host "      ____) | |_| \__ \ |   | | |  __/ |_) |  ____) | (__| |  | | |_) | |_    "
    Write-Host "     |_____/ \__, |___/_|   |_|  \___| .__/  |_____/ \___|_|  |_| .__/ \__|   "
    Write-Host "              __/ |                  | |                        | |           "
    Write-Host "             |___/                   |_|                        |_|           "
    Write-Host "                                                                              "
    Write-Host "                                                      por Marcos Vettorazzo   "
    Write-Host "                                                                              "
    Write-Host -BackgroundColor Red -ForegroundColor Black  "PSScriptRoot: " $PSScriptRoot
    Write-Host -BackgroundColor Red -ForegroundColor Black  "Origem dos Arquivos: " $Orig
    Write-Host -BackgroundColor Red -ForegroundColor Black "Status: " $tarefa
}
function Check-Files([string]$Orig, $arquivos) {

    $tarefa = "Checando arquivos em: " + $Orig
    $check_error = 0
    # $n = 1
    # Show-Banner $tarefa

    Foreach ($i in $arquivos) {

        $FileOrig = $Orig + $i
        Write-Host -BackgroundColor Green -ForegroundColor Black "Verificando arquivo " $FileOrig

        If ( Test-Path -Path $FileOrig ) {
            Write-Host -BackgroundColor Green -ForegroundColor Black "`rOK"
        } Else {
            Write-Host -BackgroundColor Red -ForegroundColor White "`r ausente."
            $check_error = $check_error + 1 
        }
        # If ( $n -gt 2 ){
        #     Show-Banner $tarefa
        #     Write-Host ""
        #     $n = 0
        # }

        # $n = $n + 1
    }
    
    If ($check_error -eq 0 ){
        Write-Host -BackgroundColor Green -ForegroundColor Black "Final Check-Files - Todos os arquivos presentes ... "
        Return $true
    } else {
        Write-Host -BackgroundColor Red -ForegroundColor White "#  ERRO!  #
Não foi possível encontrar alguns arquivos!"
        Return $false
    }
}
function Copy-Files([string]$Orig, [string]$Dest) {

    $copy_error = 0

    If ( Test-Path $Dest ){
        Write-Host "A pasta "$Dest" existe.
        Apagando conteúdo..."

        Get-ChildItem -Path "C:\Uteis" -Exclude 'Instaladores', '*CCleaner*', '*Softwares*' | Remove-Item -Recurse
        Start-Anim -num 3
        Write-Host "Fim da limpeza..."
    }

    $tarefa = "Copiando arquivos de: " + $Orig + "para: " + $Dest
    # Show-Banner $tarefa

    If ($Orig -eq $null){
        $Orig = $PSScriptRoot
    }
    
    If ($Dest -eq $null){
        $Dest = $localExecPath
    }

    Write-Host "Origem: " $Orig
    Write-Host "Destino: " $Dest

    If ( Test-Path -Path $Dest ){
        Write-Host "`rPasta "$Dest" OK"
    } Else {
        Write-Host "Pasta "$Dest" nao existe...."
        Write-Host "Criando pasta" $Dest"..."
        New-Item -ItemType Directory -Path $Dest | Out-Null
    }
    
    Write-Host "Iniciando copia dos arquivos essenciais ..."

    Foreach ($i in $arquivos) {

        $FileOrig = $Orig + $i
        $FileDest = $Dest + $i

        If (Test-Path -Path $FileDest) {
            Write-Host -BackgroundColor Red -ForegroundColor Black "Destino: " $FileDest "existe..."
            If (((Get-ItemProperty -Path $FileOrig).Extension -eq ".ps1") -Or ((Get-ItemProperty -Path $FileOrig).Extension -eq ".bat") -Or ((Get-ItemProperty -Path $FileOrig).Extension -eq ".cmd") -Or ((Get-ItemProperty -Path $FileOrig).Extension -eq ".ini")){
                Copy-Item -Path $FileOrig $FileDest -Force
                Write-Host -BackgroundColor Green -ForegroundColor White "Arquivo de script $FileDest atualizado."
            }
        } Else {
            Write-Host -BackgroundColor Red -ForegroundColor White "Destino: " $FileDest "ausente."
            Copy-Item -Path $FileOrig $FileDest
            Write-Host -BackgroundColor DarkGreen -ForegroundColor DarkYellow "Arquivo copiado."
        }

        Start-Anim -num 5

        # If ( $n -gt 2 ){
        #     Show-Banner $tarefa
        #     Write-Host ""
        #     $n = 0
        # }

        # $n = $n + 1
    }

    if ( $isKeySwInst ){
        Write-Host "Softwares já instalados?"
        Start-Anim
    } else {
        Write-Host "Iniciando cópia dos instaladores ..."

        If ( -Not (Test-Path -Path $localExecPath"\Softwares\Instaladores") ){
            New-Item -Path "C:\Uteis\Softwares\" -ItemType Directory -Name Instaladores -Force -ErrorAction SilentlyContinue | Out-Null
        }

        $SWList = Get-ChildItem -Path $Orig"\Softwares\Instaladores\"

        If ( ($SWList).Count -eq 0) {

            Foreach ($i in $softwares) {

                $FileOrig = $Orig + $i
                $FileDest = $Dest + $i

                If ( -Not (Test-Path -Path $FileDest) ) {
                    If ((Get-ItemProperty -Path $FileDest -ErrorAction SilentlyContinue | Out-Null).Length -ne (Get-ItemProperty -Path $FileOrig -ErrorAction SilentlyContinue | Out-Null).Length ){
                        Write-Host -BackgroundColor Red -ForegroundColor Black "Destino: " $FileDest "não existe. Copiando arquivo."
                        Start-BitsTransfer -Source $FileOrig -Destination $FileDest -DisplayName $FileOrig -Description $FileDest
                        Write-Host "Arquivo $i copiado."
                    }                    
                } else {
                    Write-Host "Arquivo $i já copiado."
                }

                # If ( $n -gt 2 ){
                #     Show-Banner $tarefa
                #     Write-Host ""
                #     $n = 0
                # }
                # $n = $n + 1
            }
        }
    }

    If ($copy_error -eq 0 ){
        Write-Host "Final Copy-Files - Arquivos copiados... "
        Return $true
    } else {
        Write-Host -BackgroundColor Red -ForegroundColor White "ERRO! 
        Não foi possível copiar alguns arquivos!"
        Return $false
    }
}
function Start-SWInst {

    Do {
        $keyYes  = [ConsoleKey]::S
        $keyNo = [ConsoleKey]::N
        
        Clear-Host
        Write-Host -BackgroundColor Red "#  Todos os softwares presentes em              #
#  "$localExecPath"\Softwares\Instaladores\ serão instalados!  #"
        Write-Host "
#  (S)im - Instalar os Softwares.         #
#  (N)ão - Prosseguir com a preparação.   #
"
        $keyInfo = [console]::ReadKey($true)

    } Until (($keyInfo.Key -eq $keyYes) -Or ($keyInfo.Key -eq $keyNo) )

    Switch ($keyInfo.Key) {
        "S" {
            $swList = Get-ChildItem -Path $localExecPath"\Softwares\Instaladores"

            If ( $swList -eq $null) {
                Write-Host "Não existem arquivos na pasta de Instaladores!
    Copie os arquivos para a pasta correta e"
                Pause
            }

            foreach ($swFile in $SwList) {
                
                    If (-Not (Test-Path -Path $localExecPath+'\Softwares\Instaladores\'+$swFile+'.key')){
                        
                        $swExec = Get-ItemProperty($localExecPath+'\Softwares\Instaladores\'+$swFile)

                        # If (($swExec).Extension -eq '.msi'){
                        #     $swArgs = '/quiet /passive /qb /norestart /l '+$localExecPath+'\Softwares\Instaladores\'+$swFile+'.log'
                        # } else {
                        #     $swArgs = '/s /v"/qb"'
                        # }

                        Write-Host "Instalando"
                        # swExec: $swExec
                        # swArgs: $swArgs"
                        Start-Process -Wait $swExec #-ArgumentList $swArgs
                        New-Item -Path $localExecPath'\Softwares\Instaladores\' -ItemType File -Name $swFile'.log'

                    } else {
                        Write-Host $swFile "já instalado. Continuando ..."
                    }

            }
            New-Item -Path $localExecPath -Type File -Name keySwInst 
        }
        "N" { 
            Write-Host "Ok. Pulando instalação."
            Continue
        }
    }
}
function Start-Sysprep {

        If ( (Get-Process -Name sysprep -ErrorAction SilentlyContinue) -ne $null ){
            Write-Host "O Sysprep já está em execução. Finalizando..."
            Stop-Process -Name sysprep
            } else {
            Write-Host "O Sysprep não está em execução. Continuando..."
        }

    Do {
        $keyYes  = [ConsoleKey]::S
        $keyNo = [ConsoleKey]::N
        Write-Host -ForegroundColor Red -BackgroundColor White "Processo de pre configuração terminado.
    Deseja interromper o processo para criar uma imagem antes de rodar o sysprep?"
        Write-Host Write-Host -BackgroundColor Red -ForegroundColor Yellow "#  S - Interromper para criar uma imagem.  #"
        Write-Host Write-Host -BackgroundColor Red -ForegroundColor Yellow "#  N - Continuar e rodar o SYSPREP.        #"

        $keyInfo = [console]::ReadKey($true)
    } Until ( ($keyInfo.Key -eq $keyYes) -Or ($keyInfo.Key -eq $keyNo)  )

    Switch ($keyInfo.Key) {
        "S" {
            New-Item -Path "C:\" -ItemType File -Name isPreSysprep -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path "c:\isFreshImage" -Force | Out-Null
            Copy-Item -Path C:\Uteis\Sysprep\sysprep.lnk -Destination $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup\sysprep.lnk"
            Start-Anim -num 5
            Write-Host "Reiniciando..."
            Shutdown /r /f /t 0
            Exit 0
        }
        "N" {

            Write-Host "Removendo histórico de comandos do Powershell ..."
            Remove-Item -Confirm:$false $env:APPDATA"\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "Iniciando CCleaner ..."
            Start-Process -Wait $localExecPath"\Softwares\CCleanerPortable\CCleaner64.exe"
            
            Write-Host "Iniciando limpeza de discos..."
            Start-Process -Wait powershell -ArgumentList 'C:\Windows\System32\cleanmgr.exe /sagerun:0'

            Write-Host "Iniciando otimização de discos..."
            Start-Process -Wait powershell -ArgumentList 'C:\Windows\System32\Defrag.exe C: /U /D /L /G /O'

            # Write-Host "Verificando pendêcias do Windows Update..."

            Write-Host "Iniciando Sysprep...
            O sistema será desativado ao término da tarefa..."
            New-Item -Path "c:\" -ItemType File -Name isFreshImage -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup\sysprep.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path "c:\isPreSysprep" -Force -ErrorAction SilentlyContinue | Out-Null
            C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\Uteis\sysprep\copy.xml
            Start-Anim -num 5
            Write-Host "Saindo ..."
            Exit 0
        }
    }    
}
function Start-PreDeploy {

    if ( -Not $isKeyAjustes ){

        Write-Host "Iniciando ajustes preDeploy"

        Write-Host "Ajustes\ajusta-ntp.bat"
        Start-Process -Wait $localExecPath"\Ajustes\ajusta-ntp.bat"
        
        Write-Host "Ajustes\ajusta-tzdata.bat"
        Start-Process -Wait $localExecPath"\Ajustes\ajusta-tzdata.bat"
        
        Write-Host "Ajustes\ativaAdminShare.bat"
        Start-Process -Wait $localExecPath"\Ajustes\ativaAdminShare.bat"
        
        Write-Host "Ajustes\enableScripts.bat"
        Start-Process -Wait $localExecPath"\Ajustes\enableScripts.bat"
        
        Write-Host "Samba\Windows10_SMB.ps1"
        Start-Process -Wait powershell -ArgumentList '-Command "Samba\Windows10_SMB.ps1"'

        Write-Host "Desativando hibernação..."
        powercfg.exe /hibernate off

        New-Item -Path "C:\Uteis\" -ItemType File -Name keyAjustes -Force -ErrorAction SilentlyContinue | Out-Null

    }

    if ( -Not $isKeySwInst ){
        # Instalar softwares
        Start-SWInst
    }
        
    Write-Host "Navegadores\install.ps1"
    Start-Process -Wait powershell -ArgumentList '-Command "Navegadores\install.ps1"'
    
    Write-Host "Softwares\removeApps.ps1"
    Start-Process -Wait powershell -ArgumentList '-Command "Softwares\removeApps.ps1"'
    
    Write-Host "Softwares\setFileAssoc.ps1"
    Start-Process -Wait powershell -ArgumentList '-Command "Softwares\setFileAssoc.ps1"'
    
    Write-Host "Layout\applyLayout.ps1"
    Start-Process -Wait powershell -ArgumentList '-Command "Layout\applyLayout.ps1"'

    Start-Process notepad.exe -ArgumentList "C:\Uteis\Layout\StartMenu\desktopLayout.xml"

    Write-Host "Fim pre-deploy"

    Start-Sysprep

}
function Start-PostDeploy {
    # Start-Anim
    
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

    # cria login PGE
    If ((Get-LocalUser -Name pge -ErrorAction SilentlyContinue) -eq $null) {

        Do {
            $keyYes  = [ConsoleKey]::S
            $keyNo = [ConsoleKey]::N
            Write-Host -ForegroundColor Red -BackgroundColor White "Criar usuário local PGE ?"
            Write-Host Write-Host -BackgroundColor Red -ForegroundColor Yellow "#  S - Criar usuário.  #"
            Write-Host Write-Host -BackgroundColor Red -ForegroundColor Yellow "#  N - Continuar.      #"
    
            $keyInfo = [console]::ReadKey($true)
        } Until ( ($keyInfo.Key -eq $keyYes) -Or ($keyInfo.Key -eq $keyNo)  )

        Switch ($keyInfo.Key) {
            "S" {
                Write-Host -BackgroundColor Red  "Defina a senha para o usuário PGE..."
                $pass = ConvertTo-SecureString "pge2021" -AsPlainText -Force
                New-LocalUser "pge" -Password $pass -FullName "Usuário PGE" -Description "Usuário PGE" -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
                Add-LocalGroupMember -Group "Usuários" -Member "pge" | Out-Null
                Start-Anim -num 3
                Write-Host -BackgroundColor Green -ForegroundColor White "Usuário local 'pge' criado."
            }
            "N" {
                Write-Host "Continuando..."
            }
        }

    } else {
        Write-Host "Usuário local 'pge' já existe. Continuando ..."
    }

    # WSUS & UPDATE    
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wsus = (Get-ItemProperty -Path $key -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    If ($wsus -ne 1){
        Write-Host "Configurando WSUS ..."
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\WSUS\wsus.bat'
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\WSUS\limpaWSUS.bat'
    }
    
    # KSP
    If ( -Not (Test-Path -Path "C:\Program Files (x86)\Kaspersky Lab\NetworkAgent\klnagent.exe")){
        Write-Host "Instalando Agente Kaspersky ..."
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\KSP\ksp.bat'
    }

    # VNC
    If ( -Not (Test-Path -Path "C:\Program Files\RealVNC\VNC4\winvnc4.exe")){        
        Write-Host "Instalando e configurando VNC Server ..."
        Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\VNC\vnc.bat'
    }
    
    # # ZBX
    # Write-Host "Instalando e configurando Zabbix Agent ..."
    # If ( -Not (Test-Path -Path "C:\Zabbix")){ 
    #     Start-Process -Wait powershell -ArgumentList ''
    # }

    # OCS
    If ( $hostname -Like $tag ){
        
        If ( -Not (Test-Path -Path "C:\Program Files (x86)\OCS Inventory Agent\OCSInventory.exe")){
            Write-Host "Instalando OCS ..."
            Start-Process -Wait powershell -ArgumentList 'C:\Uteis\Softwares\OCS\ocs.bat'
        } else {
            Write-Host "OCS Inventory já está instalado."
        }

    } else {

        If (-Not (Test-Path -Path "C:\Users\procuradoria\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\pre_sysprep.lnk" )){
            Write-Host "Copiando atalho para a pasta de autostart..."
            If((Copy-Item -Path "C:\Uteis\pre_sysprep.lnk" -PassThru -Destination "C:\Users\procuradoria\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\pre_sysprep.lnk") -ne $null){
                Write-Host "Atalho copiado."
                Write-Host -BackgroundColor Red "Reiniciando... O script irá iniciar automaticamente após o login."
                Start-Anim -num 5
                Shutdown /r /f /t 3
            } else {
                "Erro ao copiar o atalho!"
            }
        } else {
            "Atalho de autostart já existe."
        }
    }

    Write-Host "Apagando arquivos desnecessários..."
    Get-ChildItem -Path 'C:\Uteis' -Exclude 'Layout' | Remove-Item -Recurse -Force
    Remove-Item 'C:\Uteis\Layout\applyLayout.ps1' -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\Users\procuradoria\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\pre_sysprep.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path "C:\isFreshImage" -Force -ErrorAction SilentlyContinue | Out-Null

}

$softwares = @(
    "\Softwares\Instaladores\7z1900-x64.msi",
    "\Softwares\Instaladores\AcroRdrDC1900820071_pt_BR.exe",
    "\Softwares\Instaladores\AssinadorARISP.exe",
    "\Softwares\Instaladores\BRyExtensionModule.msi",
    "\Softwares\Instaladores\bry_signer_setup_3.1.9.0.exe",
    "\Softwares\Instaladores\ChromeStandaloneSetup64.exe",
    "\Softwares\Instaladores\Firefox Setup 78.10.1esr.msi",
    "\Softwares\Instaladores\GDsetupStarsignCUTx64.exe",
    "\Softwares\Instaladores\gemccid_en-us_64.msi",
    "\Softwares\Instaladores\InstaladorCadeias_1.0.2.0.exe",
    "\Softwares\Instaladores\jre-8u301-windows-i586.exe",
    "\Softwares\Instaladores\jre-8u301-windows-x64.exe",
    "\Softwares\Instaladores\LibreOffice_7.1.5_Win_x64.msi",
    "\Softwares\Instaladores\navegadorpje.exe",
    "\Softwares\Instaladores\OtimizadorPDFv64r97.exe",
    "\Softwares\Instaladores\pdf24-creator-9.0.1.msi",
    "\Softwares\Instaladores\pdf24-creator-9.2.0.msi",
    "\Softwares\Instaladores\pdfsam-4.0.5.msi",
    "\Softwares\Instaladores\PJeOffice.exe",
    "\Softwares\Instaladores\QWS3270plus_371.exe",
    "\Softwares\Instaladores\SafeSignIC30124-x64-win-tu-admin.exe",
    "\Softwares\Instaladores\vlc-3.0.8-win64.exe",
    "\Softwares\Instaladores\winff-x86-x64.exe"
)

$arquivos = @(
    "\Ajustes",
    "\Layout",
    "\Navegadores",
    "\Samba",
    "\Softwares",
    "\Sysprep",
    "\pre_sysprep.ps1",
    "\pre_sysprep.lnk",
    "\Ajustes\ajusta-ntp.bat",
    "\Ajustes\ajusta-tzdata.bat",
    "\Ajustes\ativaAdminShare.bat",
    "\Ajustes\enableScripts.bat",
    "\Layout\applyLayout.ps1",
    "\Layout\StartMenu",
    "\Layout\StartMenu\desktopLayout.xml",
    "\Layout\Wallpaper",
    "\Layout\Wallpaper\wallpaper.jpg",
    "\Navegadores\bookmarks.html",
    "\Navegadores\bookmarksff.json",
    "\Navegadores\install.ps1",
    "\Navegadores\chrome",
    "\Navegadores\chrome\master_preferences",
    "\Navegadores\firefox",
    "\Navegadores\firefox\autoconfig.js",
    "\Navegadores\firefox\local-settings.js",
    "\Navegadores\firefox\mozilla.cfg",
    "\Samba\Windows10_Gerenciamento_Credenciais.reg",
    "\Samba\Windows10_Netlogon.reg",
    "\Samba\Windows10_SambaDomain.reg",
    "\Samba\Windows10_SMB.ps1",
    "\Softwares\removeApps.ps1",
    "\Softwares\setFileAssoc.ps1",
    "\Softwares\CCleanerPortable",
    "\Softwares\CCleanerPortable\lang",
    "\Softwares\CCleanerPortable\lang\lang-1025.dll",
    "\Softwares\CCleanerPortable\lang\lang-1026.dll",
    "\Softwares\CCleanerPortable\lang\lang-1027.dll",
    "\Softwares\CCleanerPortable\lang\lang-1028.dll",
    "\Softwares\CCleanerPortable\lang\lang-1029.dll",
    "\Softwares\CCleanerPortable\lang\lang-1030.dll",
    "\Softwares\CCleanerPortable\lang\lang-1031.dll",
    "\Softwares\CCleanerPortable\lang\lang-1032.dll",
    "\Softwares\CCleanerPortable\lang\lang-1033.dll",
    "\Softwares\CCleanerPortable\lang\lang-1034.dll",
    "\Softwares\CCleanerPortable\lang\lang-1035.dll",
    "\Softwares\CCleanerPortable\lang\lang-1036.dll",
    "\Softwares\CCleanerPortable\lang\lang-1037.dll",
    "\Softwares\CCleanerPortable\lang\lang-1038.dll",
    "\Softwares\CCleanerPortable\lang\lang-1040.dll",
    "\Softwares\CCleanerPortable\lang\lang-1041.dll",
    "\Softwares\CCleanerPortable\lang\lang-1042.dll",
    "\Softwares\CCleanerPortable\lang\lang-1043.dll",
    "\Softwares\CCleanerPortable\lang\lang-1044.dll",
    "\Softwares\CCleanerPortable\lang\lang-1045.dll",
    "\Softwares\CCleanerPortable\lang\lang-1046.dll",
    "\Softwares\CCleanerPortable\lang\lang-1048.dll",
    "\Softwares\CCleanerPortable\lang\lang-1049.dll",
    "\Softwares\CCleanerPortable\lang\lang-1050.dll",
    "\Softwares\CCleanerPortable\lang\lang-1051.dll",
    "\Softwares\CCleanerPortable\lang\lang-1052.dll",
    "\Softwares\CCleanerPortable\lang\lang-1053.dll",
    "\Softwares\CCleanerPortable\lang\lang-1054.dll",
    "\Softwares\CCleanerPortable\lang\lang-1055.dll",
    "\Softwares\CCleanerPortable\lang\lang-1056.dll",
    "\Softwares\CCleanerPortable\lang\lang-1057.dll",
    "\Softwares\CCleanerPortable\lang\lang-1058.dll",
    "\Softwares\CCleanerPortable\lang\lang-1059.dll",
    "\Softwares\CCleanerPortable\lang\lang-1060.dll",
    "\Softwares\CCleanerPortable\lang\lang-1061.dll",
    "\Softwares\CCleanerPortable\lang\lang-1062.dll",
    "\Softwares\CCleanerPortable\lang\lang-1063.dll",
    "\Softwares\CCleanerPortable\lang\lang-1065.dll",
    "\Softwares\CCleanerPortable\lang\lang-1066.dll",
    "\Softwares\CCleanerPortable\lang\lang-1067.dll",
    "\Softwares\CCleanerPortable\lang\lang-1068.dll",
    "\Softwares\CCleanerPortable\lang\lang-1071.dll",
    "\Softwares\CCleanerPortable\lang\lang-1079.dll",
    "\Softwares\CCleanerPortable\lang\lang-1081.dll",
    "\Softwares\CCleanerPortable\lang\lang-1086.dll",
    "\Softwares\CCleanerPortable\lang\lang-1087.dll",
    "\Softwares\CCleanerPortable\lang\lang-1090.dll",
    "\Softwares\CCleanerPortable\lang\lang-1092.dll",
    "\Softwares\CCleanerPortable\lang\lang-1093.dll",
    "\Softwares\CCleanerPortable\lang\lang-1102.dll",
    "\Softwares\CCleanerPortable\lang\lang-1104.dll",
    "\Softwares\CCleanerPortable\lang\lang-1109.dll",
    "\Softwares\CCleanerPortable\lang\lang-1110.dll",
    "\Softwares\CCleanerPortable\lang\lang-1155.dll",
    "\Softwares\CCleanerPortable\lang\lang-2052.dll",
    "\Softwares\CCleanerPortable\lang\lang-2070.dll",
    "\Softwares\CCleanerPortable\lang\lang-2074.dll",
    "\Softwares\CCleanerPortable\lang\lang-3098.dll",
    "\Softwares\CCleanerPortable\lang\lang-5146.dll",
    "\Softwares\CCleanerPortable\lang\lang-9999.dll",
    "\Softwares\CCleanerPortable\x64",
    "\Softwares\CCleanerPortable\x64\CCleanerDU.dll",
    "\Softwares\CCleanerPortable\x86",
    "\Softwares\CCleanerPortable\x86\CCleanerDU.dll",
    "\Softwares\CCleanerPortable\CCleaner.exe",
    "\Softwares\CCleanerPortable\CCleaner64.exe",
    "\Softwares\CCleanerPortable\License.txt",
    "\Softwares\CCleanerPortable\portable.dat",
    "\Softwares\WSUS",
    "\Softwares\WSUS\limpaWSUS.bat",
    "\Softwares\WSUS\wsus.bat",
    "\Softwares\WSUS\WSUS-CConfig_x64.exe",
    "\Softwares\WSUS\WSUS-CConfig.sav",
    "\Softwares\VNC",
    "\Softwares\VNC\RealVNC_Enterprise.exe",
    "\Softwares\VNC\realvnc.reg",
    "\Softwares\VNC\vnc.bat",
    "\Softwares\KSP",
    "\Softwares\KSP\Agente12.exe",
    "\Softwares\KSP\ksp.bat",
    "\Softwares\OCS",
    "\Softwares\OCS\ocs.bat",
    "\Softwares\OCS\win7_8_10_ocspackage.exe",
    "\Sysprep\copy.xml",
    "\Sysprep\sysprep.ps1",
    "\Sysprep\sysprep.lnk"
    )

$localExecPath = "C:\Uteis"
$SourcePath = $PSScriptRoot
$Orig = $SourcePath
$Dest = $localExecPath

$keyFreshImage = "C:\isFreshImage"
$isFreshImage = $false
if (Test-Path -Path $keyFreshImage){
    $isFreshImage = $true
} else {
    $isFreshImage = $false
}

$keyPreSysprep = "C:\isPreSysprep"
$isPreSysprep = $false
if (Test-Path -Path $keyPreSysprep){
    $isPreSysprep = $true
} else {
    $isPreSysprep = $false
}

$keyPreDeploy = "C:\isPreDeploy"
$isPreDeploy = $false
if (Test-Path -Path $keyPreDeploy){
    $isPreDeploy = $true
} else {
    $isPreDeploy = $false
}

$keyAjustes = "C:\Uteis\keyAjustes"
$isKeyAjustes = $false
if (Test-Path -Path $keyAjustes){
    $isKeyAjustes = $true
} else {
    $isKeyAjustes = $false
}

$keySwInst = "C:\Uteis\keySwInst"
$isKeySwInst = $false
if (Test-Path -Path $keySwInst){
    $isKeySwInst = $true
} else {
    $isKeySwInst = $false
}

# Clear-Host
# Show-Banner
# Start-Anim -num 3

If ( $PSScriptRoot -ne "C:\Uteis" ) {

    If( -Not ($isFreshImage)){
        Write-Host "IsFreshImage = FALSE"
        If( -Not ($isPreSysprep)){
            Write-Host "IsPreSysprep = FALSE"

            Do {
                $keyYes  = [ConsoleKey]::S
                $keyNo = [ConsoleKey]::N
                Write-Host -BackgroundColor White -ForegroundColor Black "Instalar em disco USB?
                (S)im / (N)ão"        
                $keyInfo = [console]::ReadKey($true)
            } Until ( ($keyInfo.Key -eq $keyYes) -Or ($keyInfo.Key -eq $keyNo)  )

            If ($keyInfo.Key -ne $null){

                switch ($keyInfo.Key) {
                    's' {
                        Do {
                            Write-Host "Detectando discos USB ..."
                            $discos =  get-disk | Where-Object BusType -eq USB | get-partition | get-volume | Select-Object -Property DriveLetter,FileSystemLabel
                            $n=0
                            $letrasUnidades = @()
                            foreach ( $disco in $discos ) {                        
                                $letraDisco = $disco.DriveLetter
                                $nomeDisco = $disco.FileSystemLabel
                                $letrasUnidades += $letraDisco
                                Write-Host "Disco"$n":        "$letraDisco":\["$nomeDisco"]"
                                $n = $n+1
                            }
        
                            Write-Host -BackgroundColor Red -ForegroundColor Yellow "Tecle a letra da unidade de destino."
                            $letraUnidade = [console]::ReadKey($true)
        
                            If ($letrasUnidades -notcontains $letraUnidade.Key){
                                # # Clear-Host
                                # Show-Banner
                                Write-Host ""
                                Write-Host -BackgroundColor Red "ERRO! Unidade invalida!"
                                Write-Host "Tentando novamente ..." 
                            }
                            
                        } until ( $letrasUnidades -contains $letraUnidade.Key)
                        
                        $Dest = $letraUnidade.Key.ToString()+":\Uteis"
        
                        Copy-Files $Orig $Dest
        
                        Write-Host "Arquivos copiados...
                        Saindo ..."
                        Start-Anim -num 5
                        Exit 0 
                    }
                    'n'{
                        Continue
                    }
                }
            }
            
        }
    }

    If (Check-Files $Orig $arquivos){
        If (Copy-Files $Orig $localExecPath ){
            If(Check-Files $localExecPath $arquivos){
                Write-Host "Reiniciando script a partir de " $localExecpath
                # Start-Anim
                Set-Location $localExecPath
                & $localExecPath\pre_sysprep.ps1
            }
        } else {
            Write-Host "Falha ao copiar os arquivos!"
            Write-Host "Origem: " $Orig
            Write-Host "Destino: " $localExecPath
        }
    } else {
        Write-Host -BackgroundColor White -ForegroundColor Black "Não. Foi possível encontrar os arquivos necessarios em:" 
        Write-Host -BackgroundColor White -ForegroundColor Black $Orig 
    }

} else {
    Write-Host "Script rodando de " $PSScriptRoot
    
    If ((Get-Command -Module PSWindowsUpdate).Count -eq 0 ){
        Write-Host "Instalando PSWindowsUpdate ..."
        Install-Module -Name PSWindowsUpdate -Force -Verbose
    }

    If ((Get-Command -Module PolicyFileEditor).Count -eq 0 ){
        Write-Host "Instalando PolicyFileEditor ..."
        Install-Module -Name PolicyFileEditor -Force -Verbose
    }

    If (Check-Files $PSScriptRoot){
        If ($isFreshImage){
            Write-Host "Iniciando PostDeploy"
            Start-PostDeploy
        } else {
            If (-Not ($isPreSysprep)){ 
                Write-Host "Iniciando PreDeploy"
                Start-PreDeploy
            }
        }
    }
}

# Write-Host "Removendo C:\Uteis ..."
# Remove-Item -Force -Recurse -Path "C:\Uteis" -ErrorAction SilentlyContinue

# function Show-Menu
# {
    
#     param (
#         [string]$MenuTit = 'Titulo Menu',
#         [string]$MenuMsg = 'Mensagem Menu',
#         $MenuOptions = {
#         }
#     )

#     Write-Host "## $MenuTit"
#     Write-Host "| $MenuMsg" 
#     Write-Host "|==="
#     Foreach ($MenuOption in $MenuOptions) {
#         $MenuOptionKey,
#         $MenuOptionAction
#     }
#     Write-Host "|==="
#     Write-Host ""
    
    # do {
    #     Show-Menu
    #     $selection = Read-Host "Please make a selection"
    
#     switch ($selection)
#     {
#         $MenuOptionKey {
#             'You chose option' $MenuOptionKey
#         }
#         default { 'erro !'} 
# }

# do {
#     Show-Menu
#     $selection = Read-Host "Please make a selection"
#     switch ($selection)
#     {
#         '1' {
#             'You chose option #1'
#         } '2' {
#             'You chose option #2'
#         } '3' {
#             'You chose option #3'
#         }
#         default { 'erro !'} 

#     }
#     # Start-Anim
#     pause
# }
# until ($selection -eq 'q')


#.\
# | guia_sysprep.txt
# | post_deploy.ps1
# | pre_sysprep.ps1
# +---Ajustes
# |    ajusta-ntp.bat
# |    ajusta-tzdata.bat
# |    ativaAdminShare.bat
# |    enableScripts.bat
# |    habilitaSMBv1.ps1
# |
# +---Layout
# |   |   applyLayout.ps1
# |   |   
# |   +---StartMenu
# |   |       fullLayout.xml
# |   |       initLayout.xml
# |   |       startLayout.txt
# |   |       taskbarLayout.xml
# |   |       
# |   \---Wallpaper
# |           wallpaper.jpg
# |
# +---Navegadores
# |   |   bookmarks.html
# |   |   bookmarksff.json
# |   |   install.ps1
# |   |   
# |   +---chrome
# |   |       master_preferences
# |   |       
# |   \---firefox
# |           autoconfig.js
# |           local-settings.js
# |           mozilla.cfg
# | 
# \---Samba
#         Windows10_Gerenciamento_Credenciais.reg
#         Windows10_Netlogon.reg
#         Windows10_SambaDomain.reg
#         Windows10_SMB.ps1
# +---Softwares
# |       removeApps.ps1
# |       setFileAssoc.ps1
# |
# \---Sysprep
#        copy.xml
#        sysprep.ps1