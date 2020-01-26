cscript SetMsiProperty.js Setup\DseSetup\SetupCloud\Release\SetupCloud.msi  MSIUSEREALADMINDETECTION 1
cscript SetMsiProperty.js Setup\DseSetup\SetupCloud\Release\SetupCloud.msi  REBOOT "Force"
cscript SetMsiProperty.js Setup\DseSetup\SetupCloud\Release\SetupCloud.msi  FolderForm_AllUsers  "All"
