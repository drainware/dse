cscript SetMsiProperty.js Setup\DseSetup\SetupCloud32\Release\SetupCloud32.msi  MSIUSEREALADMINDETECTION 1
cscript SetMsiProperty.js Setup\DseSetup\SetupCloud32\Release\SetupCloud32.msi  REBOOT "Force"
cscript SetMsiProperty.js Setup\DseSetup\SetupCloud32\Release\SetupCloud32.msi  FolderForm_AllUsers  "All"
