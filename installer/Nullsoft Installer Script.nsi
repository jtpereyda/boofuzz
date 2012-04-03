; Sulley Fuzzing Framework Installer
; Aaron Portnoy
; TippingPoint Security Research Team
; (c) 2007

; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "Sulley Fuzzing Framework"
!define PRODUCT_VERSION "1.0"
!define PRODUCT_PUBLISHER "Pedram Amini and Aaron Portnoy"
!define PRODUCT_WEB_SITE "http://www.fuzzing.org"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\Sulley.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI 1.67 compatible ------
!include "MUI.nsh"

; ZIP support
!include "ZipDLL.nsh"

!define MUI_ABORTWARNING

; icons
!define MUI_ICON "..\..\sulley_icon.ico"
!define MUI_UNICON "..\..\sulley_icon.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "..\LICENSE.txt"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_RUN
; Run on completion
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchDocsAndShell"
!insertmacro MUI_PAGE_FINISH
; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES
; Language files
!insertmacro MUI_LANGUAGE "English"



Function LaunchDocsAndShell
   ExecShell "" "$INSTDIR\docs\index.html"
   Exec 'cmd.exe /c cd "$INSTDIR"'
FunctionEnd

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "Sulley Fuzzing Framework.exe"
InstallDir "$PROGRAMFILES\Sulley Fuzzing Framework"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show


Section "Sulley" SEC01
   SetOutPath "$INSTDIR\install_files"
   File "install_files\python.msi"
   File "install_files\winpcap.exe"
   File "install_files\pcapy.exe"
   File "install_files\ctypes.exe"
   SetOutPath "$INSTDIR"
   File "sulley.zip"
   ZipDLL::extractall "$INSTDIR\sulley.zip" "$INSTDIR"
SectionEnd


Section "Python" SEC02
  SetOverwrite ifnewer
  ExecWait 'msiexec /i "$INSTDIR\install_files\python.msi"'
SectionEnd

Section "Pcapy" SEC03
  SetOverwrite ifnewer
  ExecWait  "$INSTDIR\install_files\pcapy.exe"
SectionEnd

Section "WinPCAP" SEC04
  SetOverwrite ifnewer
  ExecWait  "$INSTDIR\install_files\winpcap.exe"
SectionEnd

Section "ctypes" SEC05
  SetOverwrite ifnewer
  ExecWait "$INSTDIR\install_files\ctypes.exe"
SectionEnd


Section -AdditionalIcons
  SetOutPath $INSTDIR
  WriteIniStr "$INSTDIR\${PRODUCT_NAME}.url" "InternetShortcut" "URL" "${PRODUCT_WEB_SITE}"
  CreateShortCut "$SMPROGRAMS\Sulley Fuzzing Framework\Website.lnk" "$INSTDIR\${PRODUCT_NAME}.url"
  CreateShortCut "$SMPROGRAMS\Sulley Fuzzing Framework\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$PROGRAMFILES\pcapy-0.10.5.win32-py2.5.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$PROGRAMFILES\pcapy-0.10.5.win32-py2.5.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd


Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "Sulley was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove Sulley and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  RMDir /r "$INSTDIR"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd