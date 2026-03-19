[Setup]
AppName=HotZone Pro
AppVersion=1.0
DefaultDirName={autopf}\HotZone Pro
DefaultGroupName=HotZone Pro
OutputDir=Output
OutputBaseFilename=HotZonePro_Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
DisableProgramGroupPage=yes

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "dist\HotZonePro\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\HotZone Pro"; Filename: "{app}\HotZonePro.exe"
Name: "{autodesktop}\HotZone Pro"; Filename: "{app}\HotZonePro.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\HotZonePro.exe"; Description: "{cm:LaunchProgram,HotZone Pro}"; Flags: nowait postinstall skipifsilent
