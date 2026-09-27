!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\runtime\install.ps1" -Action Install -PackageRoot "$INSTDIR\runtime"'
  Pop $0
  Pop $1
  StrCmp $0 "0" konsollink_runtime_installed
  MessageBox MB_OK|MB_ICONSTOP "KonsolLink runtime installation failed (exit $0):$\r$\n$1"
  Abort
konsollink_runtime_installed:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\runtime\install.ps1" -Action Uninstall'
  Pop $0
  Pop $1
  StrCmp $0 "0" konsollink_runtime_removed
  MessageBox MB_OK|MB_ICONSTOP "KonsolLink service removal failed (exit $0):$\r$\n$1"
  Abort
konsollink_runtime_removed:
!macroend
