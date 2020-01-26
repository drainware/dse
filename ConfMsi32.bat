cscript SetMsiProperty.js Setup32\Release\Setup32.msi  MSIUSEREALADMINDETECTION 1
cscript SetMsiProperty.js Setup32\Release\Setup32.msi  REBOOT "Force"
cscript SetMsiProperty.js Setup32\Release\Setup32.msi  FolderForm_AllUsers  "All"


REM cscript SetMsiProperty.js Setup32\Release\Setup32.msi setProperty MSIUSEREALADMINDETECTION 1
REM cscript SetMsiProperty.js Setup32\Release\Setup32.msi setProperty REBOOT "Force"
REM cscript SetMsiProperty.js Setup32\Release\Setup32.msi setProperty FolderForm_AllUsers  "All"
