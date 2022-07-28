
Write-Host "Importando Windows10_Gerenciamento_Credenciais.reg ..."
Start-Process -Wait reg.exe -ArgumentList "import $localexecPath\Softwares\Samba\Windows10_Gerenciamento_Credenciais.reg"

Write-Host "Importando Windows10_Netlogon.reg ..."
Start-Process -Wait reg.exe -ArgumentList "import $localexecPath\Softwares\Samba\Windows10_Netlogon.reg"

Write-Host "Importando Wndows10_SambaDomain.reg ..."
Start-Process -Wait reg.exe -ArgumentList "import $localexecPath\Softwares\Samba\Windows10_SambaDomain.reg"

Write-Host "Importando Wndows10_SambaHardened.reg ..."
Start-Process -Wait reg.exe -ArgumentList "import $localexecPath\Softwares\Samba\Windows10_SambaHardened.reg"

Write-Host "Ativando suporte ao protocolo SMBv1 ..."
# Desabilitar:	Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
# Habilitar:	
Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName SMB1Protocol

Write-Host "Fim SMBv1..."
Start-Sleep 3
