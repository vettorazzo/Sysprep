If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

if($env:PROCESSOR_ARCHITECTURE -eq "x86"){
    # $arch = "x86"
    $path = "C:\Program Files (x86)\Mozilla Firefox"
}Else{
    # $arch = "x64"
    $path = "C:\Program Files\Mozilla Firefox"
}

If (Test-Path -Path $path){

    # Write-Host "# Firefox" $arch
    # C:\Program Files\Mozilla Firefox\

    #                                 -\mozilla.cfg
    Copy-Item -Path "\\10.38.24.7\repo\sysprep\Navegadores\firefox\mozilla.cfg" -Destination $path

    
    #                                 -\defaults\pref\autoconfig.js
    #                                 -\defaults\pref\local-settings.js
    Copy-Item -Path "\\10.38.24.7\repo\sysprep\Navegadores\firefox\autoconfig.js" -Destination $path"\defaults\pref" 
    Copy-Item -Path "\\10.38.24.7\repo\sysprep\Navegadores\firefox\local-settings.js" -Destination $path"\defaults\pref\" 

    #                                 -\defaults\profile\bookmarks.html
    # If ( -Not (Test-Path -Path $path"\defaults\profile\" )){
    #     New-Item -ItemType "Directory" -Path $path"\defaults\profile"
    # }
    # Copy-Item -Path "\\10.38.24.7\repo\sysprep\Navegadores\bookmarks.html" -Destination $path"\defaults\profile\"
}