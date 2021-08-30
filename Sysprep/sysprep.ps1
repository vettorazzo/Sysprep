if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

Do {
    $keyYes  = [ConsoleKey]::S
    $keyNo = [ConsoleKey]::N
    Write-Host Write-Host -BackgroundColor Red -ForegroundColor Yellow "#  Iniciar o sysprep ?(S/N)  #"

    $keyInfo = [console]::ReadKey()
} Until ( ($keyInfo.Key -eq $keyYes) -Or ($keyInfo.Key -eq $keyNo)  )

Switch ($keyInfo.Key) {
    "S" {
        Write-Host "Removendo histórico de comandos do Powershell ..."
            Remove-Item -Confirm:$false $env:APPDATA"\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "Iniciando CCleaner ..."
            Start-Process -Wait $localExecPath"\Softwares\CCleanerPortable\CCleaner64.exe"
            
            Write-Host "Iniciando limpeza de discos..."
            Start-Process -Wait powershell -ArgumentList 'C:\Windows\System32\cleanmgr.exe /sagerun:0'
        
            Write-Host "Iniciando otimização de discos..."
            Start-Process -Wait powershell -ArgumentList 'C:\Windows\System32\Defrag.exe C: /U /D /L /G /O'

            Write-Host "Iniciando Sysprep...
            O sistema será desativado ao término da tarefa..."
            New-Item -Path "c:\" -ItemType File -Name isFreshImage -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup\sysprep.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
            Remove-Item -Path "c:\isPreSysprep" -Force -ErrorAction SilentlyContinue | Out-Null
            C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\Uteis\sysprep\copy.xml
            Start-Sleep -s 5
            Write-Host "Saindo ..."
            Exit 0
        }
    "N" {
        Write-Host "Saindo ..."
        Exit 0
    }
}