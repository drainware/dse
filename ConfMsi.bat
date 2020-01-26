cscript SetMsiProperty.js Setup\Release\Setup.msi  MSIUSEREALADMINDETECTION 1
cscript SetMsiProperty.js Setup\Release\Setup.msi  REBOOT "Force"
cscript SetMsiProperty.js Setup\Release\Setup.msi  FolderForm_AllUsers  "All"


REM cscript SetMsiProperty.js Setup\Release\Setup.msi setProperty MSIUSEREALADMINDETECTION 1
REM cscript SetMsiProperty.js Setup\Release\Setup.msi setProperty REBOOT "Force"
REM cscript SetMsiProperty.js Setup\Release\Setup.msi setProperty FolderForm_AllUsers  "All"
