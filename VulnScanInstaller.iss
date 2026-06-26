; VulnScanInstaller.iss
; Inno Setup script — builds a professional Windows installer
; Compile this with Inno Setup to produce VulnScanSetup.exe

#define AppName "VulnScan"
#define AppVersion "1.0.0"
#define AppAuthor "Usman Zaffar"
#define AppExeName "VulnScan.exe"
#define SourceDir "dist\VulnScan"

[Setup]
; Basic app info
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppAuthor}
AppPublisherURL=https://github.com/yourusername/vulnscan
AppSupportURL=https://github.com/yourusername/vulnscan
AppUpdatesURL=https://github.com/yourusername/vulnscan/releases

; Where it installs to
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}

; Output installer file
OutputDir=C:\Users\732usman(pc)\Desktop\vulnscan\installer_output
OutputBaseFilename=VulnScanSetup_v{#AppVersion}

; Compression — makes installer smaller
Compression=lzma2/ultra64
SolidCompression=yes

; Windows version requirement
MinVersion=10.0

; Installer window settings
WizardStyle=modern
WizardResizable=no

; Allow user to choose install dir
DisableDirPage=no

; Show license page
; LicensePage=license.txt

; Don't require admin rights
; Users can install without being admin
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Let users choose whether to create desktop icon
Name: "desktopicon"; \
  Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; \
  Flags: unchecked

[Files]
; Include everything from the PyInstaller output folder
Source: "{#SourceDir}\*"; \
  DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu shortcut
Name: "{group}\{#AppName}"; \
  Filename: "{app}\{#AppExeName}"

Name: "{group}\Uninstall {#AppName}"; \
  Filename: "{uninstallexe}"

; Desktop shortcut (only if user chose it)
Name: "{autodesktop}\{#AppName}"; \
  Filename: "{app}\{#AppExeName}"; \
  Tasks: desktopicon

[Run]
; Offer to launch app after install
Filename: "{app}\{#AppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up the database and reports folder when uninstalling
Type: filesandordirs; Name: "{app}\reports"
Type: files; Name: "{app}\vulnscan.db"

[Messages]
; Custom installer messages
WelcomeLabel1=Welcome to {#AppName} Setup
WelcomeLabel2=This will install {#AppName} v{#AppVersion} by {#AppAuthor} on your computer.%n%nVulnScan is a professional vulnerability scanner that checks open ports, detects services, looks up CVEs, and checks targets against VirusTotal.%n%nClick Next to continue.
FinishedHeadingLabel=Setup Complete
FinishedLabel={#AppName} has been installed on your computer.%n%nYou will be prompted to accept the legal notice when you first launch the app.%n%nRemember: only scan systems you own or have permission to test.