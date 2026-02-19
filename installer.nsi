!include "MUI2.nsh"

Name "WinVolAuto"
OutFile "WinVolAuto_Setup.exe"
InstallDir "$PROGRAMFILES64\WinVolAuto"
RequestExecutionLevel admin

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "resources\EULA.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "dist\WinVolAuto\*.*"
  
  CreateShortcut "$DESKTOP\WinVolAuto.lnk" "$INSTDIR\WinVolAuto.exe"
  
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$DESKTOP\WinVolAuto.lnk"
  RMDir /r "$INSTDIR"
SectionEnd
