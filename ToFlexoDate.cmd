rename Setup\Release\Setup.msi Setup%1.msi
rename Setup32\Release\Setup32.msi Setup32%1.msi
rename SetupCloud\Release\SetupCloud.msi SetupCloud%1.msi
rename SetupCloud32\Release\SetupCloud32.msi SetupCloud32%1.msi

copy Setup\Release\Setup%1.msi \\flexo\public\dlp\
copy Setup32\Release\Setup32%1.msi \\flexo\public\dlp\
copy SetupCloud\Release\SetupCloud%1.msi \\flexo\public\dlp\
copy SetupCloud32\Release\SetupCloud32%1.msi \\flexo\public\dlp\