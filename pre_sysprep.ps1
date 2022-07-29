<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">

<settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <CopyProfile>true</CopyProfile>
        <AutoLogon>
        <Password>
        <Value>procurando2016</Value>
        </Password>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>procuradoria</Username>
        </AutoLogon>        
    </component>
</settings>

<settings pass="offlineServicing">
    <component name="Microsoft-Windows-LUA-Settings" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <EnableLUA>false</EnableLUA>
    </component>
</settings>

<settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <InputLocale>pt_BR:ABNT2</InputLocale>
        <SystemLocale>pt_BR</SystemLocale>
        <UILanguage>pt_BR</UILanguage>
        <UserLocale>pt_BR</UserLocale>
    </component>

    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <OOBE>
            <HideEULAPage>true</HideEULAPage>
            <HideLocalAccountScreen>true</HideLocalAccountScreen>
            <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
            <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
            <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
            <NetworkLocation>Work</NetworkLocation>
            <ProtectYourPC>3</ProtectYourPC>
            <UnattendEnableRetailDemo>false</UnattendEnableRetailDemo>
        </OOBE>
        
        <UserAccounts>
            <LocalAccounts>
                <LocalAccount wcm:action="add">
                    <Password>
                        <Value>procurando2016</Value>
                        <PlainText>true</PlainText>
                    </Password>
                    <Description></Description>
                    <DisplayName>procuradoria</DisplayName>
                    <Group>Administrators</Group>
                    <Name>procuradoria</Name>
                </LocalAccount>
            </LocalAccounts>
        </UserAccounts>
        
        <RegisteredOrganization>PGE</RegisteredOrganization>
        <RegisteredOwner>procuradoria</RegisteredOwner>
        <DisableAutoDaylightTimeSet>false</DisableAutoDaylightTimeSet>
        <FirstLogonCommands>
            <SynchronousCommand wcm:action="add">
            <Order>1</Order>
            <RequiresUserInput>false</RequiresUserInput>
            <CommandLine>cmd /C wmic useraccount where name="procuradoria" set PasswordExpires=false</CommandLine>
            <Description>Password Never Expires</Description>
            </SynchronousCommand>

            <SynchronousCommand wcm:action="add">
            <Description>Control Panel View</Description>
            <Order>2</Order>
            <CommandLine>reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /t REG_DWORD /d 1 /f</CommandLine>
            <RequiresUserInput>true</RequiresUserInput>
            </SynchronousCommand>

            <SynchronousCommand wcm:action="add">
            <Order>3</Order>
            <Description>Control Panel Icon Size</Description>
            <RequiresUserInput>false</RequiresUserInput>
            <CommandLine>reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /t REG_DWORD /d 1 /f</CommandLine>
            </SynchronousCommand>

            <SynchronousCommand wcm:action="add">
            <Order>4</Order>
            <Description>Copy pre_sysprep.lnk</Description>
            <RequiresUserInput>false</RequiresUserInput>
            <CommandLine>C:\Uteis\task_pos_sysprep.bat</CommandLine>
            </SynchronousCommand>

            <SynchronousCommand wcm:action="add">
            <Order>5</Order>
            <Description>Enable FOG</Description>
            <RequiresUserInput>false</RequiresUserInput>
            <CommandLine>C:\Uteis\enableFOG.bat</CommandLine>
            </SynchronousCommand>
        </FirstLogonCommands>
        
        <TimeZone>E. South America Standard Time</TimeZone>
    </component>
</settings>

</unattend>
