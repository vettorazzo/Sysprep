#
$localPath = "C:\Uteis\Layout\StartMenu\"
$remotePath = "\\10.38.24.7\repo\Sysprep\Layout\StartMenu\"

$path = $localPath

# # layout inicial pré-definido
# $fullLayout = $path + "Layout.xml"
# # Export-Layout pós edição
# $startLayout = $path + "startLayout.xml"

# #cabeçalho correto
# $initLayout = $path + "initLayout.xml"
# Get-Content $fullLayout -First 6 | Out-File $initLayout

# # rodapé (aka: taskbar pins) correto
# $taskbarLayout = $path + "taskbarLayout.xml"
# Get-Content $fullLayout -Last 13 | Out-File $taskbarLayout

# resultado da mesclagem dos arquivos
$desktopLayout = $path + "desktopLayout.xml"

# $MachineDir = "$env:windir\system32\GroupPolicy\Machine\registry.pol"
$UserDir = "$env:windir\system32\GroupPolicy\User\registry.pol"

$pol01 = @('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer','LockTaskbar',1,'DWord')
$pol02 = @('Software\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoChangeStartMenu',1,'DWord')
$pol03 = @('Software\Policies\Microsoft\Windows\Explorer','LockedStartLayout',1,'DWord')
$pol04 = @('Software\Policies\Microsoft\Windows\Explorer','StartLayoutFile',$desktopLayout,'ExpandString')

Remove-PolicyFileEntry -Path $UserDir -Key $pol01[0] -ValueName $pol01[1]
Remove-PolicyFileEntry -Path $UserDir -Key $pol02[0] -ValueName $pol02[1]
Remove-PolicyFileEntry -Path $UserDir -Key $pol03[0] -ValueName $pol03[1]
Remove-PolicyFileEntry -Path $UserDir -Key $pol04[0] -ValueName $pol04[1]

Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "LockedStartLayout" -Force
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "StartLayoutFile" -Force

# C:\Windows\System32\gpupdate.exe

# Write-Host "Importando layout ..."
Import-StartLayout -LayoutPath $desktopLayout -MountPath C:\

Write-Host "Parando Windows Explorer..."
Write-Host "Aguarde..."
Stop-Process -ProcessName explorer
Start-Sleep -s 10

# Write-Host -ForegroundColor Red -BackgroundColor White "Edite o menu Iniciar.
# Quando terminar digite sim e pressione ENTER."

# $continue = Read-Host 
# while($continue -ne "sim")
# {
#     Write-Host -ForegroundColor Red -BackgroundColor White "Edite o menu Iniciar.
# Quando terminar digite sim e pressione ENTER."
#     $continue = Read-Host 
# }

# Write-Host "OK. Exportando novo layout ..."
# Export-StartLayout -Path $startLayout

# Write-Host "Removendo primeira linha ..."
# $content = Get-Content $startLayout
# $content[1..($content.length-1)]|Out-File $startLayout -Force

# Write-Host "Removendo ultima linha ..."
# $content = Get-Content $startLayout
# $content[0..($content.length-2)] | Out-File $startLayout -Force

# Write-Host "Concatenando arquivos"
# Get-Content $initLayout, $startLayout, $taskbarLayout | Set-Content $desktopLayout

# Write-Host "Removendo ultima linha ...
# Outra vez ..."
# $content = Get-Content $desktopLayout
# $content[0..($content.length-2)] | Out-File $desktopLayout -Force

Write-Host "Importando arquivo final de layout ..."

# Export-StartLayout -Path $desktopLayout
Import-StartLayout -LayoutPath $desktopLayout -MountPath C:\

Set-PolicyFileEntry -Path $UserDir -Key $pol01[0] -ValueName $pol01[1] -Data $pol01[2] -Type $pol01[3]
Set-PolicyFileEntry -Path $UserDir -Key $pol02[0] -ValueName $pol02[1] -Data $pol02[2] -Type $pol02[3]
Set-PolicyFileEntry -Path $UserDir -Key $pol03[0] -ValueName $pol03[1] -Data $pol03[2] -Type $pol03[3]
Set-PolicyFileEntry -Path $UserDir -Key $pol04[0] -ValueName $pol04[1] -Data $pol04[2] -Type $pol04[3]

C:\Windows\System32\gpupdate.exe

Stop-Process -ProcessName explorer
Start-Sleep -s 10

Stop-Process -ProcessName explorer
Start-Sleep -s 10

Write-Host "Personalizanção finalizada ..."
