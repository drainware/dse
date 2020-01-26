git pull
git submodule init
git submodule update

call "c:\Program Files (x86)\Microsoft Visual Studio 11.0\VC\vcvarsall.bat" x86_amd64

devenv DrainwareSecurityEndpoint.sln /Clean "Release|Win32"
devenv DrainwareSecurityEndpoint.sln /Clean "Release|x64"
devenv DrainwareSecurityEndpoint.sln /Build "Release|Win32"
devenv DrainwareSecurityEndpoint.sln /Build "Release|x64"

rem devenv DrainwareSecurityEndpoint.sln /Clean "Debug|Win32"
rem devenv DrainwareSecurityEndpoint.sln /Clean "Debug|x64"
rem devenv DrainwareSecurityEndpoint.sln /Build "Debug|Win32"
rem devenv DrainwareSecurityEndpoint.sln /Build "Debug|x64"


cd Setup\DseSetup
call "c:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat" x86_amd64

devenv DseSetup.sln /Clean "Release|Default"
devenv DseSetup.sln /Build "Release|Default"


cd ../..
rem cmd /c ConfMsi32.bat
rem cmd /c ConfMsi.bat
cmd /c ConfMsiCloud.bat
cmd /c ConfMsiCloud32.bat
@echo Signing installers

"C:\Program Files (x86)\Windows Kits\8.0\bin\x86\signtool.exe"  sign /ph /ac "C:\Program Files (x86)\Windows Kits\8.0\crosscertificates\DigiCert_High_Assurance_EV_Root_CA.crt" /sha1 "CA38CA2428F195F985C7E48F9788266ACFD120D6" /t "http://timestamp.digicert.com" Setup\DseSetup\SetupCloud\Release\SetupCloud.msi
"C:\Program Files (x86)\Windows Kits\8.0\bin\x86\signtool.exe"  sign /ph /ac "C:\Program Files (x86)\Windows Kits\8.0\crosscertificates\DigiCert_High_Assurance_EV_Root_CA.crt" /sha1 "CA38CA2428F195F985C7E48F9788266ACFD120D6" /t "http://timestamp.digicert.com" Setup\DseSetup\SetupCloud32\Release\SetupCloud32.msi


@echo Drainware Security Endpoint Build!!!
pause