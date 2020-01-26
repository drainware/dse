<?PHP
/*
 * v1.0
 * cryptam.php: MalwareTracker.com Cryptam - command line script
 * Main script to call for document analysis command line usage: 
 * php cryptam.php <filename> [data element to display/defaults to
 * all when blank]
 */


$global_magic_file = "file"; //magic file
$global_yara_cmd = '/opt/local/bin/yara -s -m';
$global_yara_sig = '';

ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_COMPILE_ERROR|E_ERROR|E_CORE_ERROR);


ini_set('pcre.backtrack_limit', 10000000);
ini_set('pcre.recursion_limit', 10000000);
ini_set('memory_limit', '256M');



$global_true_keys = array('00fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a898887868584838281807f7e7d7c7b7a797877767574737271706f6e6d6c6b6a696867666564636261605f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201',
'f4f3f2f182868b9aecebeae99a8e8392e4e3e2e192b6bbaadcdbdad9aabeb3a2d4d3d2d1a2a6abbacccbcac9baaea3b2c4c3c2c1b2d6dbcabcbbbab9caded3c2b4b3b2b1c2c6cbdaacabaaa9dacec3d2a4a3a2a1d2f6fbea9c9b9a99eafef3e294939291e2e6ebfa8c8b8a89faeee3f284838281f2161b0a7c7b7a790a1e13027473727102060b1a6c6b6a691a0e03126463626112363b2a5c5b5a592a3e33225453525122262b3a4c4b4a493a2e23324443424132565b4a3c3b3a394a5e53423433323142464b5a2c2b2a295a4e43522423222152767b6a1c1b1a196a7e73621413121162666b7a0c0b0a097a6e63720403020172969b8afcfbfaf98a9e9382',
'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
'a7a6a5a4a3a2a1a05f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241407f7e7d7c7b7a797877767574737271706f6e6d6c6b6a69686766656463624b601f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201003f3e3d3c3b3a393837363534333231302f2e2d2c2b2a29282726252423222120dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0fffefdd6fbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8');

if (!function_exists('hex2bin')) {
	function hex2bin($h) {
		if (!is_string($h))
			return null;
		$r='';
		$len = strlen($h);
		for ($a=0; $a<$len; $a+=2) {
			if ($a+1 < $len)
				$r.=chr(hexdec($h{$a}.$h{($a+1)}));
		}
	  	return $r;
	}
}


$global_engine = 26;


$cryptam_executable_sigs = array(
'This program cannot be run in DOS mode'=>'string.This program cannot be run in DOS mode', 
'This program must be run under Win32'=>'string.This program must be run under Win32',
'LoadLibraryA'=>'string.LoadLibraryA', 
'GetModuleHandleA'=>'string.GetModuleHandleA', 
'GetCommandLineA'=>'string.GetCommandLineA', 
'GetSystemMetrics'=>'string.GetSystemMetrics', 
'GetProcAddress'=>'string.GetProcAddress', 
'CreateProcessA'=>'string.CreateProcessA', 
'URLDownloadToFileA'=>'string.URLDownloadToFileA', 
'EnterCriticalSection'=>'string.EnterCriticalSection', 
'GetEnvironmentVariableA'=>'string.GetEnvironmentVariableA',
'CloseHandle'=>'string.CloseHandle',
'CreateFileA'=>'string.CreateFileA',
'URLDownloadToFileA'=>'string.URLDownloadToFileA',
'Advapi32.dll'=>'string.Advapi32.dll',
'RegOpenKeyExA'=>'string.RegOpenKeyExA',
'RegDeleteKeyA'=>'string.RegDeleteKeyA',
'user32.dll'=>'string.user32.dll',
'shell32.dll'=>'string.shell32.dll',
'KERNEL32'=>'string.KERNEL32',
'ExitProcess'=>'string.ExitProcess',
'GetMessageA'=>'string.GetMessageA',
'CreateWindowExA'=>'string.CreateWindowExA',
hex2bin('504500004C010100')=> 'string.PE Header',
'hTsip orrgmac naon tebr nui  nOD Somed' => 'string.transposition cipher of This program cannot be run in DOS mode',
//hex2bin('A2434B9B0183937B3B930B6B011B0B73737BA301132B0193AB73014B7301227A9A016B7B232B') => 'string.cipher of This program cannot be run in DOS mode',
//hex2bin('627B0B23624B13930B93CB0A') => 'string.cipher of LoadLibraryA',
//hex2bin('3A2BA382937B1B0A2323932B9B9B') => 'string.cipher of GetProcAddress',
//hex2bin('2AC34BA382937B1B2B9B9B') => 'string.cipher of ExitProcess',
'/Developer/SDKs/MacOSX10.5.sdk/usr/include/libkern/i386/_OSByteOrder.h'=>'string.MacOSX10.5.sdk',
'__gcc_except_tab__TEXT'=>'string._gcc_except_tab__TEXT',
'/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices'=>'string.CoreServices.framework',
'/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'=>'string.CoreFoundation.framework',
'@_getaddrinfo'=>'string.etaddrinfo',
'@_pthread_create'=>'string.pthread_create',
'StartupParameters.plist'=>'string.StartupParameters.plist',
'dyld__mach_header'=>'string.dyld__mach_header',
'/usr/lib/libSystem'=>'string./usr/lib/libSystem',
'/usr/lib/dyld'=>'string./usr/lib/dyld',
'__PAGEZERO'=>'string.__PAGEZERO',
'/usr/lib/libgcc_s'=>'string./usr/lib/libgcc_s',
'<key>RunAtLoad</key>'=>'string.RunAtLoad',
'__mh_execute_header'=>'string.__mh_execute_header',

);


$cryptam_plaintext_sigs = array (
'w:ocx w:data="DATA:application/x-oleobject'=>'exploit.office OLE application command',
'Scripting.FileSystemObject' => 'exploit.office embedded Visual Basic write to file Scripting.FileSystemObject',
'Wscript.Shell' => 'exploit.office embedded Visual Basic execute shell command Wscript.Shell',
'OpenTextFile' => 'exploit.office embedded Visual Basic accessing file OpenTextFile',
'netsh firewall set opmode mode=disable' => 'exploit.office shell command netsh disable firewall',
'ScriptBridge.ScriptBridge.1' => 'exploit.office ScriptBridge may load remote exploit',
'cmd.exe /c' => 'exploit.office cmd.exe shell command',
hex2bin("0600DDC6040011000100D65A12000000000001000000060000000300") => 'exploit.office smarttag overflow CVE-2006-2492',
hex2bin("0600C8BE1B0008000200685B1200") => 'exploit.office smarttag overflow CVE-2006-2492',
'\x4F\x72\x69\x65\x6E\x74\x61\x74\x69\x6F\x6E.\x50\x4F\x33(.{1}?)' => 'exploit.office excel buffer overflow CVE-2009-3129',
'\x66\x55\x66\x55.{3}?\x00\x43\x57\x53' => 'suspicious.flash CWS flash in MS Office document',
'\x66\x55\x66\x55.{3}?\x00\x46\x57\x53' => 'suspicious.flash FWS flash in MS Office document',
hex2bin("076A69745F656767") => 'suspicious.flash jit_egg',
hex2bin('4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134') => 'flash.exploit CVE-2011-0609 A',

hex2bin('7772697465427974650541727261799817343635373533304143433035303030303738') => 'flash.exploit CVE-2011-0611 B', 
hex2bin('5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348') => 'flash.exploit CVE-2011-0611 C',
hex2bin('343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431') => 'flash.exploit CVE-2011-0611 D',

hex2bin('3063306330633063306330633063306306537472696E6706') => 'flash.exploit CVE-2011-0611 E', 
hex2bin('410042004300440045004600470048004900A18E110064656661756C74') => 'flash.exploit CVE-2011-0611 F', 
hex2bin('00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277') => 'flash.exploit CVE-2011-0611 G', 
hex2bin('34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235') => 'flash.exploit CVE-2011-0609 B', 
hex2bin('3941303139413031394130313941303139064C6F61646572') => 'flash.exploit CVE-2011-0609 C', 

'AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB' => 'flash.exploit CVE-2011-0611 A',

hex2bin("537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E") => 'exploit.flash flash calling malformed MP4 CVE-2012-0754 A',
'sn .{1,300}?pFragments.{1,700}?sv .{1,200}?[a-zA-Z0-9\*\+]{50}' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333',
'\sn\*\sn-pFragments' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 B',

'pFragments.{1,200}?\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x0D\x0A' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 B',

'sn pfragments.{1,30}?11111111' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 C',

'sn[\W]{1,20}?pFragments' => 'exploit.office RTF stack overflow pFragments CVE-2010-3333 D',


'objdata.{1,350}?5\w*3\w*4\w*3\w*6\w*F\w*6\w*D\w*6\w*3\w*7\w*4\w*6\w*C\w*4\w*C\w*6\w*9\w*6\w*2\w*2\w*E\w*4\w*C' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158',


'objdata.{1,100}?53436F6D63746C4C69622E4C' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158',


'objdata.{1,300}?\w*5\w*0\w*6\w*1\w*6\w*3\w*6\w*b\w*6\w*1\w*6\w*7\w*6\w*5\w*0\w*0' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 B',

'ListView2, 1, 1, MSComctlLib, ListView' => 'exploit.office CVE-2012-0158 C',



'0000000000000000000000000000000000000000000000.{1,300}?49746D736400000002000000010000000C000000436F626A' => 'exploit.office RTF MSCOMCTL.OCX RCE CVE-2012-0158 D',


'\xEC\xBD\x01\x00\x05\x00\x90\x17\x19\x00\x00\x00\x08\x00\x00\x00\x49\x74\x6D\x73\x64\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x0C\x00\x00\x00\x43\x6F\x62\x6A.\x00\x00\x00\x82\x82\x00\x00\x82\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.{4}?\x90' => 'exploit.office OLE MSCOMCTL.OCX RCE CVE-2012-0158',

'\x31\x31\x31\x31\x31\x31\x31\x31\x31\x0D\x0D\x0D\x13\x20\x43\x4F\x4E\x54\x52\x4F\x4C\x20\x4D\x53\x43\x6F\x6D\x63\x74\x6C\x4C\x69\x62\x2E\x4C\x69\x73\x74\x56\x69\x65\x77\x43\x74\x72\x6C\x2E\x32.{1}?' => 'exploit.office OLE MSCOMCTL.OCX RCE CVE-2012-0158',
hex2bin('4D006900630072006F0073006F0066007400200042006100730065002000430072007900700074006F0067007200610070006800690063002000500072006F0076006900640065007200200076') => 'suspicious.office encrypted document',

'\x45\x78\x61\x6D\x70\x6C\x65\x0B\x63\x72\x65\x61\x74\x65\x4C\x69\x6E\x65\x73\x09\x68\x65\x61\x70\x53\x70\x72\x61\x79\x08\x68\x65\x78\x54\x6F\x42\x69\x6E\x07\x6D\x78\x2E\x63\x6F\x72\x65\x0A\x49\x46\x6C\x65\x78\x41\x73\x73\x65\x74\x09\x46\x6F\x6E\x74\x41\x73\x73\x65\x74\x0A\x66\x6C\x61\x73\x68\x2E\x74\x65\x78\x74.{1}?'  => 'flash.exploit CVE-2012-1535',

'\x45\x4D\x42\x45\x44\x44\x45\x44\x5F\x43\x46\x46\x0A\x66\x6F\x6E\x74\x4C\x6F\x6F\x6B\x75\x70\x0D\x45\x6C\x65\x6D\x65\x6E\x74\x46\x6F\x72\x6D\x61\x74\x08\x66\x6F\x6E\x74\x53\x69\x7A\x65\x0B\x54\x65\x78\x74\x45\x6C\x65\x6D\x65\x6E\x74\x07\x63\x6F\x6E\x74\x65\x6E\x74\x0E\x63\x72\x65\x61\x74\x65\x54\x65\x78\x74\x4C\x69\x6E\x65\x08\x54\x65\x78\x74\x4C\x69\x6E\x65\x01\x78\x01\x79\x06\x68\x65\x69\x67\x68\x74\x08\x61\x64\x64\x43\x68\x69\x6C\x64\x06\x45\x6E\x64\x69\x61\x6E\x0D\x4C\x49\x54\x54\x4C\x45\x5F\x45\x4E\x44\x49\x41\x4E\x06\x65\x6E\x64\x69\x61\x6E\x22\x30\x63\x30\x63\x30\x63\x30\x63.{1}?' => 'flash.exploit CVE-2012-1535',

'MSComctlLib.TabStrip' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856',
'4d53436f6d63746c4c69622e546162537472697' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856 hex',
'9665fb1e7c85d111b16a00c0f0283628' => 'exploit.office MSCOMCTL.OCX TabStrip CVE-2012-1856 A',

'\x8A\x23\xAB\xA7\x8A\x01\x90\x8B\x23\xEE\xD4\x61\xD8\x87\x23\x96\xA3\x9A\x02\xF4\x85\x23\xA1\xF9\x4A\xB4\x83\x23\xFB\xE0\xE3\x03.{1}?'  => 'flash.exploit CVE-2013-0634 memory corruption',

'\x77\x72\x69\x74\x65\x44\x6F\x75\x62\x6C\x65\x08\x4D\x61\x74\x72\x69\x78\x33\x44\x06\x4F\x62\x6A\x65\x63\x74\x0B\x66\x6C\x61\x73\x68\x2E\x6D\x65\x64\x69\x61\x05\x53\x6F\x75\x6E\x64\x0C\x66\x6C\x61\x73\x68\x2E\x73\x79\x73\x74\x65\x6D\x0C\x43\x61\x70\x61\x62\x69\x6C\x69\x74\x69\x65\x73\x07\x76\x65\x72\x73\x69\x6F\x6E\x0B\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65\x10\x77\x69\x6E.{1}?'  => 'flash.exploit CVE-2012-5054 Matrix3D',


);



function validateFileType($filename) {
	global $global_magic_file;
	$content_type_arr = explode(': ', exec("$global_magic_file ".escapeshellarg($filename)));
	if (isset($content_type_arr[1]))
		$content_type = $content_type_arr[1];
	else
		$content_type = "data";

	if (stristr($content_type, 'executable'))
		return -1;

	return 0;
}

function getFileType($filename) {
	global $global_magic_file;
	$content_type_arr = explode(': ', exec("$global_magic_file ".escapeshellarg($filename)));
	if (isset($content_type_arr[1]))
		$content_type = $content_type_arr[1];
	else
		$content_type = 'data';

	return $content_type;
}


function getFileMetadata($filename) {
	global $global_magic_file;
	exec("$global_magic_file ".escapeshellarg($filename), $file_arr2);
	$file_arr = implode("\n", $file_arr2);
	$file = explode( ', ', $file_arr);
	$out = '';
	for($i = 2; $i < count($file); $i++) {
		$out .= $file[$i]."\n";
	}
	return $out;
}


//alt quick scan - do read of 256 block and throw away when 50% or more is zero, or all blocks are FF, or 20.
function ingestData($data, $try_len=1024, &$blocks='') {
	$table = array();

	//build data structure
	for ($i = 0; $i < $try_len; $i++) {
		$table[$i] = array();
	}

	$j = 0;

	$blocking = array();
	$b = 0;

	$distribution = array();
	//echo "Filesize: ".strlen($data)."\n";


	//collect data
	for ($i = 0; $i < strlen($data); $i++) {
		if (isset($distribution[ord($data[$i])]) )
			$distribution[ord($data[$i])] += 1;
		else
			$distribution[ord($data[$i])] = 1;

		if ($i == 0 || $i % $try_len == 0) {
			//echo "special 1 $i\n";
			$sff = 0;
			$s20 = 0;
			$s00 = 0;
			$sas = 0;
			$top = $i+$try_len;
			if ($top > strlen($data))
				$top = strlen($data);
			for ($k = $i; $k < $top; $k++) {
				$cur = ord($data[$k]);
				//echo "[$k $cur]\n";
				if ($cur == 0) {
					$s00++;
					
				} else if ($cur == 20) {
					$s20++;
					
				} else if ($cur == 255) {
					$sff++;
				} else if (ctype_print($data[$k])) {
					$sas++;
				}
			}
			if ($s00 -4 > $try_len/3) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else if ($sff-4 > $try_len/3) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else if ($s20-4 > $try_len/3) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else if ($sas-4 > $try_len*0.98) {
				$i+= $try_len-1;
				$blocking[$b] = 0;
				$b++;
				$j=0;
			} else {
   				if ($j == $try_len) {
					$j = 0;
					$blocking[$b] = 1;
					$b++;
				}
				$cur = ord($data[$i]);
		//echo "$j $i\n";
				if (isset($table[$j][$cur]))
					$table[$j][$cur] += 1;
				else
					$table[$j][$cur] = 1;
	

				//echo "$i $j\n";
				$j++;
			}
			//echo "special 2\n";

		} else {

   			 if ($j == $try_len) {
				$j = 0;
				$b++;
				$blocking[$b] = 1;
			}
			$cur = ord($data[$i]);
		//echo "$j $i $cur ".$data[$i]."\n";
			if (isset($table[$j][$cur]))
				$table[$j][$cur] += 1;
			else
				$table[$j][$cur] = 1;
	
			$j++;
			//echo "$i $j\n";
			
		}
		

	}

	//show distribution
	//echo "Blocking\n";
	$h = 0;
	$h2 = 0;
	$blocks = '';
	foreach ($blocking as $block => $stat) {
		$blocks .= $stat;
		if ($stat == 1)
			$h++;
		else {
			if ($h > $h2)
				$h2 = $h;
			$h = 0;
		}

	}
	if ($h > $h2)
		$h2 = $h;
	//echo "\n End blocking $h\n";
	//echo "blocking $h2\n";

	//sort by occurences
	for ($i = 0; $i < $try_len; $i++) {
		arsort($table[$i]);
	}

	//var_dump($table); 

	$table['distribution'] = $distribution;
	return $table;
}




function topHits($array = array(), $max_len = 5) {

	$len = count($array);

	if ($len > $max_len) $len = $max_len;

	$total = 0;
	$cur = 0;

	foreach($array as $char => $hits) {
		$total += $hits;
		$cur++;
		if ($cur == $len) break;
	}

	$table = array();
	$cur = 0;
	$i = 0;
	foreach($array as $char => $hits) {
		//$table[$char] = number_format($hits/$total *100,2);
		$table[$i] = array ($char => number_format($hits/$total *100,2), 'hits' => $hits, 'char' => $char, 'percent' => number_format($hits/$total *100,2), 'total' =>$total);

		$cur++;
		if ($cur == $len) break;
		$i++;
	}

	return $table;

}


function analyseByte($table, $need_len) {
	$cur_len = count($table);



	if ($cur_len != $need_len)
		$byte = realignTable($table, $need_len);
	else
		$byte = $table;


	//echo "Analyse byte: $need_len, $cur_len, ".count($byte)."\n";




	$final = array();
	//$misses = 0;
	$rank = 0;
	//echo "\n==== $need_len =====\n";
	for ($i = 0; $i < $need_len; $i++) {
		$top = topHits($byte[$i], 5);

		//echo "\n[@".dechex($i)."]\n";
		if (isset($top[0]) && isset($top[1])) {
			if (dechex($top[0]['char']) == '00' || dechex($top[0]['char']) == '0' || dechex($top[0]['char']) == '20')
				$final[$i] = array('key_rank' => 0, 'char' => $top[0]['char'], 'percent' => '0');		
			else {
				$final[$i] = array('key_rank' => number_format((($top[0]['percent']-$top[1]['percent'])/10),0), 'char' => $top[0]['char'],
						'hits' => $top[0]['hits'], 'total' => $top[0]['total'], 'percent' => $top[0]['percent'], 'next' => $top[1]['char'], 'next_hits'=> $top[1]['hits']);
			}
			/*echo "\n$i RANK ".$final[$i]['key_rank']."\n";
			foreach($top as $loc => $topar) {
				echo "$loc ".dechex($topar['char'])." ".$topar['hits']." ".$topar['percent']."\n";
			
			}*/
			$rank += $final[$i]['key_rank'];
		
		} else if (isset($top[0])) {
			if (dechex($top[0]['char']) == '00' || dechex($top[0]['char']) == '0' || dechex($top[0]['char']) == '20')
				$final[$i] = array('key_rank' => 0, 'char' => $top[0]['char'], 'percent' => '');		
			else {
				$final[$i] = array('key_rank' => 10, 'char' => $top[0]['char'],
						'hits' => $top[0]['hits'], 'total' => $top[0]['total'], 'percent' => $top[0]['percent']);
			}
		}
		
	}
	//echo "Misses $misses\n";
	//echo "Rank $rank\n";
	$final['key_rank'] = $rank;
	return $final;
}



function realignTable($table, $to_len) {

	$from_len = count($table);
	echo "realign from $from_len to $to_len\n";
	$table_new = array();

	//build data structure
	for ($i = 0; $i < $to_len; $i++) {
		$table_new[$i] = array();
	}

	$j = 0;

	//collect data
	for ($i = 0; $i < $from_len; $i++) {
		foreach($table[$i] as $char => $hits) {
			if (!isset($table_new[$j][$char]))
				$table_new[$j][$char] = $hits;
			else
				$table_new[$j][$char] += $hits;
		}
		$j++;
   		if ($j == $to_len)
			$j = 0;

	}


	//sort by occurences
	for ($i = 0; $i < $to_len; $i++) {
		arsort($table_new[$i]);
	}

	return $table_new;
}






//this gets top matches in most crypto files, some cases get less matches than expected ref ef403a0c255d83b45b0c14c43e214f7d
//could add 1024 range to statistical anlysis and check for 256 or smaller keys...
function cryptoStat($data, $try_len=4) {


	$md5 = md5($data);
	$sha1 = sha1($data);
	$sha256 = hash("sha256", $data);


	//check blocking for parts of file with high entropy
	$blocks = '';
	$table = ingestData($data, 1024, $blocks);

	$distribution = $table['distribution'];
	unset ($table['distribution']);

	//var_dump($distribution);

	$exploits = ptScanFile($data);
	//var_dump($exploits);
	$rank = $exploits['rank'];
	unset($exploits['rank']);
 	$is_malware = 0;

	if ($rank > 0) {
		//echo "DETECTED MALWARE RANK $rank plaintext\n";
		$is_malware = 1;
		//return array('is_malware' => 1, 'key_len' => 0, 'key' => '',
		//	'exploits' => $exploits);
	} 


	//echo "rank=$rank\n";

	$res = analyseByte($table, 1024);//1024
	//echo count($res)."\n";

	//var_dump($res);

		


	if (isset($res['key_rank']) && $res['key_rank'] > 100) {
		//echo "DETECTED MALWARE RANK ".$res['key_rank']." encrypted\n";
		$is_malware = 1;
	} else if (isset($res['key_rank']) && $res['key_rank'] >= 1) {
		//echo "suspicious RANK ".$res['key_rank']." encrypted\n";
		$is_malware = 1;
	} else if (isset($res['key_rank']) && $is_malware != 1) {
		//echo "CLEAN RANK ".$res['key_rank']."\n";
		return array('is_malware' => 0, 'key_len' => 0, 'key' => '');
	} else  if ($is_malware != 1) {
		//echo "CLEAN\n";
		return array('is_malware' => 0, 'key_len' => 0, 'key' => '');
	}
	//var_dump($res);

	if ($is_malware == 1) {
		$scan = findKey($res);

		if ($scan['key'] != '') {
			$scan['key_occ'] = substr_count($data,hex2bin($scan['key']));
			$scan['key_entropy'] = checkEntropy($scan['key']);
			$scan['key_hash'] = md5(normalizeKey($scan['key']));

		} else
			$scan['key_len'] = 0;


		$scan['key_rank'] = $res['key_rank'];
		$scan['is_malware'] = 1;
		$scan['key_blocks'] = $blocks;
		$scan['md5'] = $md5;
		$scan['sha1'] = $sha1;
		$scan['sha256'] = $sha256;
		$scan['exploits'] = $exploits;
		$scan['h_distribution'] = '';
		$topd = 0;
		for ($i = 0; $i < 256; $i++) {
			if (isset($distribution[$i])) {
				$scan['h_distribution'] .= $distribution[$i].",";
				if ($distribution[$i] > $topd)
					$topd = $distribution[$i];
			} else
				$scan['h_distribution'] .= "0,";
		}
		$scan['h_distribution'] .= "$topd,"; //ceiling item

		$scan['h_dispersion'] = '';
		for ($i = 0; $i < count($res)-1; $i++) {
			if (isset($res[$i]['char'])) {
				$scan['h_dispersion'] .= $res[$i]['char'].",".$res[$i]['percent'].",";
			} else
				$scan['h_dispersion'] .= "0,0,";

		}



		if ($scan['key'] == 00) {
				//check for encrypted FF space where an embedded .doc file is encrypted and whitespace is not encoded
				preg_match_all("/[\\00]{400}.{70,80}\\x00\\x00\\x00[^\\00]{1}\\x00\\x00\\x00(.{432})/s", rtrim($data), $match, PREG_OFFSET_CAPTURE);

				//var_dump($matches);
				if (isset($match[1][0])) {
					foreach($match[1] as $matches0) {
						if (isset($matches0[1])) {
							$l = $matches0[1];
							$len = strlen($matches0[0]);
							$extract = strhex($matches0[0]);
							$mentropy = checkEntropy($extract);
							//echo "found @ $l $len bytes of potential cipher text with entropy $mentropy\n";
							if ($mentropy > 90.0 && $l > 512) {
								//echo $extract."\n";
								$bytes = 0;

								if (substr_count($extract,substr($extract, 0, 2)) >= 430) {
									//echo "one byte\n";
									$bytes = 1;
	
								} else if (substr_count($extract,substr($extract, 0, 4)) >= 215) {
									//echo "two byte\n";
									$bytes = 2;

								} else if (substr_count($extract,substr($extract, 0, 6)) >= 144) {
									//echo "three byte\n";
									$bytes = 3;

								} else if (substr_count($extract,substr($extract, 0, 8)) >= 102) {
									//echo "four byte\n";
									$bytes = 4;

								} else if (substr_count($extract,substr($extract, 0, 10)) >= 82) {
									//echo "four byte\n";
									$bytes = 5;
								} else if (substr_count($extract,substr($extract, 0, 12)) >= 68) {
									//echo "four byte\n";
									$bytes = 6;
								} else if (substr_count($extract,substr($extract, 0, 14)) >= 55) {
									//echo "four byte\n";
									$bytes = 7;
								} else if (substr_count($extract,substr($extract, 0, 16)) >= 50) {
									//echo "eight byte\n";
									$bytes = 8;
	
								} else if (substr_count($extract,substr($extract, 0, 32)) >= 25) {
									//echo "sixteen byte\n";
									$bytes = 16;

								} else if (substr_count($extract,substr($extract, 0, 64)) >= 11) {
									//echo "thirtytwo byte\n";
									$bytes = 32;

								} else if (substr_count($extract,substr($extract, 0, 128)) >= 4) {
									//echo "64 byte\n";
									$bytes = 64;

								} else if (substr_count($extract,substr($extract, 0, 256)) >= 3) {
									//echo "128 byte\n";
									$bytes = 128;

								} else if (substr($extract, 0, 352) == substr($extract, 513, 352 )) {	
									
									//echo "256 byte\n";
									$bytes = 256;

								}
								if ($bytes > 0) {
									$key = substr($extract, 0, $bytes*2);
									//echo "key length = $bytes\n";
									//echo "key=$key\n";
									//echo "correcting for FF space key leak with bitwise not\n";
									$key = strhex(cipherNot(hex2str($key)));
									//echo "corrected key=$key\n";
									$keyloc = $l;
									$offset = $l % $bytes;
									//echo "key offset $offset for $l\n";
									if ($offset != 0)
										$key = substr($key, -$offset*2).substr($key, 0, ($bytes-$offset)*2);
									//echo "location corrected key=$key\n";

		
									$scan['key'] = $key;
									$scan['key_occ'] = substr_count($data,hex2bin($scan['key']));
									$scan['key_entropy'] = checkEntropy($scan['key']);
									$scan['key_hash'] = md5(normalizeKey($scan['key']));
									$scan['key_zero'] = 1;
									$scan['key_len'] = $bytes;
									$scan['key_rank'] = 256;
									$scan['is_malware'] = 1;
								}
							}
						}
					}
				}
		}


		return $scan;
			
	} else {
		return array('is_malware' => 0, 'key_len' => 0, 'key' => '');



	}
	


}


function keyPivot($key, $len) {

	$data = array();
	if ($len == strlen($key))
		return $key;


	$j = 0;
	for($i = 0; $i < strlen($key); $i+=2) {
		if ($j % $len == 0) $j = 0;
		$char = hexdec($key[$i].$key[$i+1]);
		if (!isset($data[$j]) )
			$data[$j] = array();
		else if (isset($data[$j][$char]) )
			$data[$j][$char] += 1;
		else
			$data[$j][$char] = 1;
		$j++;
	}
	for ($i = 0; $i < $len; $i++) {
		arsort($data[$i]);
	}
	$newkey = '';

	for ($i = 0; $i < $len; $i++) {
		foreach ($data[$i] as $c => $h) {
			if ($h == 1) {
				$newkey .= "00";
			} else {
				$hex = dechex($c);
					if (strlen($hex) == 1)
						$hex = "0".$hex;
				$newkey .= $hex;
			}
			break;
		}
	}

	//echo "$newkey\n";
	return $newkey;
}



function findKey($res) {
		$extract = '';
		$bytes = 1024;
		foreach ($res as $pos => $data) {

			if ("$pos" != 'key_rank') {
				//echo $data['char'];
				$hex = dechex($data['char']);
				if (strlen($hex) == 1)
					$hex = "0".$hex;
				$extract .= $hex;
			}

		}


		$top256 = keyPivot($extract,256);


		$keyRefactoring = array(
			'1' => array('key' => keyPivot($extract,1)),
			'2' => array('key' => keyPivot($extract,2)),
			'3' => array('key' => keyPivot($extract,3)),
			'4' => array('key' => keyPivot($extract,4)),
			'5' => array('key' => keyPivot($extract,5)),
			'6' => array('key' => keyPivot($extract,6)),
			'7' => array('key' => keyPivot($extract,7)),
			'8' => array('key' => keyPivot($extract,8)),
			'16' => array('key' => keyPivot($extract,16)),
			'32' => array('key' => keyPivot($extract,32)),
			'64' => array('key' => keyPivot($extract,64)),
			'128' => array('key' => keyPivot($extract,128)),
			'256' => array('key' => $top256),
			'512' => array('key' => substr($extract, 0, 1024)),
			'1024' => array('key' => $extract),
			);


		foreach ($keyRefactoring as $kl => $k) {
			$keyRefactoring[$kl]['similar'] = substr_count($extract,$k['key']);
			$keyRefactoring[$kl]['percent'] = $keyRefactoring[$kl]['similar'] * $kl / 1024 * 100;
		}

		$keyRefactoring['256a'] = array('key' => $top256, 'similar' => similar_text($top256,substr($extract, 0, 512)));
		$keyRefactoring['256a']['percent'] = $keyRefactoring['256a']['similar'] / 512 * 100;
		$keyRefactoring['256b'] = array('key' => $top256, 'similar' => similar_text($top256, substr($extract, 512, 512)));
		$keyRefactoring['256b']['percent'] = $keyRefactoring['256b']['similar'] / 512 * 100;
		$keyRefactoring['256c'] = array('key' => $top256, 'similar' => similar_text($top256, substr($extract, 1024, 512)));
		$keyRefactoring['256c']['percent'] = $keyRefactoring['256c']['similar'] / 512 * 100;
		$keyRefactoring['256d'] = array('key' => $top256, 'similar' => similar_text($top256, substr($extract, 1536, 512)));
		$keyRefactoring['256d']['percent'] = $keyRefactoring['256d']['similar'] / 512 * 100;
		$keyRefactoring['512']['similar'] = similar_text(substr($extract, 0, 1024), substr($extract, 1025, 1024));
		$keyRefactoring['512']['percent'] = $keyRefactoring['512']['similar'] / 1024 * 100;

		logdebug(print_r($keyRefactoring, TRUE));

		if ($keyRefactoring['2']['similar'] >= 250) {
			//echo "two byte\n";
			$bytes = 2;

		} else if ($keyRefactoring['3']['similar'] >= 200) {
			//echo "three byte\n";
			$bytes = 3;

		} else if ($keyRefactoring['4']['similar'] >= 100) {
			//echo "four byte\n";
			$bytes = 4;
		} else if ($keyRefactoring['5']['similar'] >= 80) {
			//echo "four byte\n";
			$bytes = 5;
		} else if ($keyRefactoring['6']['similar'] >= 80) {
			//echo "four byte\n";
			$bytes = 6;
		} else if ($keyRefactoring['7']['similar'] >= 70) {
			//echo "four byte\n";
			$bytes = 7;
		} else if ($keyRefactoring['8']['similar'] >= 60) {
			//echo "eight byte\n";
			$bytes = 8;

		} else if ($keyRefactoring['16']['similar'] >= 50) {
			//echo "sixteen byte\n";
			$bytes = 16;

		} else if ($keyRefactoring['32']['similar'] >= 25) {
			//echo "thirtytwo byte\n";
			$bytes = 32;

		} else if ($keyRefactoring['64']['similar'] >= 12) {
			//echo "64 byte\n";
			$bytes = 64;

		} else if ($keyRefactoring['128']['similar'] >= 6) {
			//echo "128 byte\n";
			$bytes = 128;

		} else if ($keyRefactoring['256a']['similar'] > 417 ||
			$keyRefactoring['256b']['similar'] > 417 ||
			$keyRefactoring['256c']['similar'] > 417 ||
			$keyRefactoring['256d']['similar'] > 417) {	
			
			//echo "256 byte\n";
			$bytes = 256;

		} else if ($keyRefactoring['1']['similar'] >= 375) {
			//echo "one byte\n";
			$bytes = 1;

		} else if ($keyRefactoring['512']['similar'] > 1000 ) {
			//echo "512 byte\n";
			$bytes = 512;

		} else {
			//echo "1024 byte\n";
			$bytes = 1024;
		}

	if ($bytes == 2 && $keyRefactoring['2']['key'][0].$keyRefactoring['2']['key'][1] == $keyRefactoring['2']['key'][2].$keyRefactoring['2']['key'][3])
		$bytes = 1;

	if ($bytes == 1024)
		return array('key_len' => $bytes, 'key' => $extract);

	return array('key_len' => $bytes, 'key' => $keyRefactoring[$bytes]['key']);
	
}

function checkEntropy($str) {
	$cnt = 0;
	for ($i = 0; $i < strlen($str); $i+=2) {
		if ($str[$i] == "0" && $str[$i+1] == "0")
			$cnt++;
	}
	//echo "$cnt\n";
	return (1-($cnt/(strlen($str)/2))) * 100;
}




//search for clear text signatures
function ptScanFile($string) {
	global $cryptam_executable_sigs, $cryptam_plaintext_sigs, $global_engine;
	$rank = 0;

	$hits = array();

	foreach($cryptam_plaintext_sigs as $search => $desc) {
		if (strstr($search, '?')) {
			preg_match("/$search/is", $string, $matches, PREG_OFFSET_CAPTURE);
			//var_dump($matches);
			if (isset($matches['0']['0']) ) {
				//echo "$desc\n";
				$l = $matches['0']['1'];
				$rank += 301;

				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregex', 'exploit' => $desc,
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc,
 							'hit_encoding' => 'string');


			}
		} else if ($l = stripos($string, $search)) {
				//echo "$desc\n";
				$rank += 300;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptstring', 'exploit' => $desc,
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc,
 							'hit_encoding' => 'string');

		}
	}


	foreach($cryptam_executable_sigs as $search => $desc) {
		if (strstr($search, '?')) {
			preg_match("/$search/is", $string, $matches, PREG_OFFSET_CAPTURE);
			//var_dump($matches);
			if (isset($matches['0']['0']) ) {
				$l = $matches['0']['1'];
				//echo "$desc\n";
				$rank += 400;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregex', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 
 							'hit_encoding' => 'string', 'exploit_type' => 'string',
						'hit_desc' => $desc);

			}
		} else {

			 if ($l = strpos($string, $search)) {
				//echo "$desc\n";
				$rank += 400;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptstring', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 
 							'hit_encoding' => 'string', 'exploit_type' => 'string',
						'hit_desc' => $desc);
			}

			for($i = 1; $i <= 7; $i++) {
				$rolsearch = cipherRol($search, $i);
				if ($rolsearch != $search) {
					if ($l = strpos($string, $rolsearch)) {
						$rank += 400;
						$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptrol', 
							'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "rol"."$i.".$desc,
 							'hit_encoding' => 'rol'.$i);
					}
				}
				$notsearch = cipherNot($search);
				if ($l = strpos($string, $notsearch)) {
					$rank += 400;
					$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptnot', 
						'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "not.".$desc,
 						'hit_encoding' => 'not');
		
				}
			
			}

		}
	}


	//check for xor look ahead cipher
	$lookAhead = xorAheadString($string);
	foreach($cryptam_executable_sigs as $search => $desc) {
		if (!strstr($search, '?')) {
			 if ($l = strpos($lookAhead, $search)) {
				//echo "$desc\n";
				$rank += 400;
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorlaptstring', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 
 							'hit_encoding' => 'xorla', 'exploit_type' => 'string',
						'hit_desc' => "xorla.".$desc);
			}

		}
	}
	unset($lookAhead);

	//decompress flash and scan with plaintext sigs
	if (preg_match_all("/\\x00\\x00CWS(.*)\\x00\\x00\\x00\\x00\\x00\\x00\\x00/s", $string, $match, PREG_OFFSET_CAPTURE)) {
		if (isset($match[1])) {
			foreach($match[1] as $matches0) {
				if (isset($matches0[1])) {
					//echo $matches0[1]." CWS".$matches0[0];
					$unc = flashExplode("CWS".$matches0[0]);
					//echo $unc;
					$loc = $matches0[1];

					foreach($cryptam_plaintext_sigs as $search => $desc) {
						if (stristr($search, '?')) {
							preg_match("/$search/is", $unc, $matches, PREG_OFFSET_CAPTURE);
							//var_dump($matches);
							if (isset($matches['0']['0']) ) {
								//echo "$desc\n";
								$l = $matches['0']['1']+$loc;
								$rank += 301;

								$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'ptregexflash', 'exploit' => "cws.".$desc,
									'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "cws.".$desc,
 											'hit_encoding' => 'string', 'flash' => base64_encode($unc), 'flash_loc' => $loc);


							}
						} else if ($l = stripos($unc, $search)) {
								//echo "$desc\n";
								$rank += 300;
								$hits[$l] = array('exploit_loc' => $l+$loc, 'searchtype' => 'ptstringflash', 'exploit' => "cws.".$desc,
									'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "cws.".$desc,
 											'hit_encoding' => 'string', 'flash' => base64_encode($unc), 'flash_loc' => $loc);

						}
					}
				}
			}
		}
	}




	$hits['rank'] = $rank;
	return $hits;

}



function hex2str($hex) {
	$str = '';
	for($i = 0; $i<strlen($hex); $i += 2) {
		$str .= chr(hexdec(substr($hex,$i,2)));
	}
	return $str;
}

function xorString($data, $key, $zero = 0) {
	$key_len = strlen($key);
	$newdata = '';
 
	if ($key_len == 0)
		return $data;
	for ($i = 0; $i < strlen($data); $i++) {
        	$rPos = $i % $key_len;
		$r = '';
		if ($key_len == 1) {
			if ($zero == 0 || $data[$i] != "\x00")
				$r = ord($data[$i]) ^ ord($key);
			else 
				$r = ord($data[$i]);
		} else
			$r = ord($data[$i]) ^ ord($key[$rPos]);
 
		$newdata .= chr($r);
	}
 
	return $newdata;
}


function xorAheadString($data) {
	$newdata = '';
 
	for ($i = 0; $i < strlen($data)-1; $i++) {
 		$r =  ord($data[$i]) ^ ord($data[$i+1]) ;
 		$newdata .= chr($r);
	}
 
	return $newdata;
}



function untranspose($string) {

	$newstring = '';
	for ($i = 0; $i < strlen($string); $i+=2){
 		$newstring .= $string[$i+1].$string[$i];
	}
	return $newstring;
}


function cipherRol($string, $x) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++){
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = substr($bin, $x).substr($bin, 0, $x);
 		$newstring .= chr(bindec($ro));
    }
    return $newstring;
}


function cipherRor($string, $x) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = substr($bin, -$x).substr($bin, 0, -$x);
		$newstring .= chr(bindec($ro));
	}
	return $newstring;
}

function cipherNot($string) {
	$newstring = '';
	for ($i = 0; $i < strlen($string); $i++) {
		$bin = str_pad(decbin(ord($string[$i])), 8,'0', STR_PAD_LEFT);
		$ro = '';
		for ($j = 0; $j < 8; $j++) {
			if ($bin[$j] == 1)
				$ro .= 0;
			else
				$ro .= 1;
		}
		$newstring .= chr(bindec($ro));
	}
	return $newstring;
}





function normalizeKey($key) {
	$values = hex2str($key).hex2str($key);
	$size= strlen($values) / 2;
	$high = chr(0x00);
	$highest = '';
	$highestLoc = 0;
	for ($j = 0; $j < $size; $j++) {
		for ($i = 0; $i < $size; $i++) {
			if (strlen($highest) > 0) {
				$check = substr($values,$i,strlen($highest));
				if ($highest == $check) {
					$pos = $i+strlen($highest);
					if ($values[$pos] > $high) {
						$highestLoc = $i-1;
						$high = $values[$pos];
					}
				}
			} else {
				if ($values[$i] > $high) {
					$highestLoc = $i-1;
					$high = $values[$i];

				}
			}

		}
		$highest .= $high;
		$high = chr(0x00);
		
		$search = '';
		for ($l = 0; $l < strlen($highest); $l++) {
			$search .= "\x".dechex(ord($highest[$l]));
		}

		if (preg_match_all("/$search/s", $values, $matches, PREG_OFFSET_CAPTURE)) {
			if (count($matches[0]) <= 2) {
				break;
			}
		}
	}

	$new = '';
	for($i = $highestLoc+1; $i < $highestLoc+$size+1; $i++) {
		$new .= $values[$i];
	}
	return strhex($new);
}

function strhex($string) {
	$hex = '';
	$len = strlen($string);
   
	for ($i = 0; $i < $len; $i++) {
		$hex .= str_pad(dechex(ord($string[$i])), 2, 0, STR_PAD_LEFT);
	}
	return $hex;
    
}


function scanFile($data, $key) {
	global $cryptam_executable_sigs, $global_engine;


	$unxor = xorString($data, hex2str($key));
	$hits = array();


	if (strlen($key) == 0)
		return $hits;

	//echo "<P>Checking for xored signatures</P>\n";
	foreach ($cryptam_executable_sigs as $search => $desc) {
		if ($l = strpos($unxor, $search)) {

				//echo "<P>Found $desc as $l</P>\n";

				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorstring', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => $desc, 'hit_encoding' => 'string');



		}
		for($i = 1; $i <= 7; $i++) {
			$rolsearch = cipherRol($search, $i);
			if ($rolsearch != $search) {
				if ($l = strpos($unxor, $rolsearch)) {
					$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorrol', 
						'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "rol"."$i.".$desc, 							'hit_encoding' => 'rol'.$i);
				}
			} //else
				//echo "<P>warn $i $search = $rolsearch</P>\n";
		}
		$notsearch = cipherNot($search);
		if ($l = strpos($unxor, $notsearch)) {
			$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xornot', 
				'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "not.".$desc,
				'hit_encoding' => 'not');

		} 


	}
	return $hits;

}




function scanXORByte($data) {
	global $cryptam_executable_sigs, $global_engine;

	$hits = array();

	$rxor = '';

	foreach ($cryptam_executable_sigs as $searchorig => $desc) {

		for($k = 1; $k < 256; $k++) {
			$search = xorString($searchorig, chr($k));
			$xor = sprintf("%02x", $k);


			if ($l = strpos($data, $search)) {
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorb', 
					'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "xor_0x".$xor.".".$desc, 'hit_encoding' => "xor_0x".$xor);
				$rxor = $xor;
			}
			for($i = 1; $i <= 7; $i++) {
				$rolsearch = cipherRol($search, $i);
				if ($rolsearch != $search) {
					if ($l = strpos($data, $rolsearch)) {
						$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorbrol', 
							'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "xor_0x".$xor.".rol".$i.".".$desc, 											'hit_encoding' => "xor_0x".$xor.'.rol'.$i);
						$rxor = $xor;
					}
				} 
			}
			$notsearch = cipherNot($search, $i);
			if ($l = strpos($data, $notsearch)) {
				$hits[$l] = array('exploit_loc' => $l, 'searchtype' => 'xorbnot', 
				'hit_id' => '1', 'hit_engine' => $global_engine, 'hit_desc' => "xor_0x".$xor.".not".".".$desc,
 				'hit_encoding' => "xor_0x".$xor.'.not');
				$rxor = $xor;
			} 


		}


	}
	$hits['xor'] = $rxor;
	return $hits;

}




function key_align($s = "provided", $t = "true known key") {

	$shortest = get_longest_common_subsequence($t, $s);

	$l = strpos($s, $shortest[0]);
	$l2= strpos($t, $shortest[0]);

	//echo "l= $l , l2 = $l2\n";
	$start = $l2-$l;
	if ($start < 0)
		$start+=strlen($s);
	return substr($t.$t, $start, strlen($s));
}

function get_longest_common_subsequence($string_1, $string_2) {
        $string_1_length = strlen($string_1);
        $string_2_length = strlen($string_2);
        $return          = array();
 
        if ($string_1_length === 0 || $string_2_length === 0) {
                // No similarities
                return $return;
        }
 
        $longest_common_subsequence = array();
 
        // Initialize the CSL array to assume there are no similarities
        for ($i = 0; $i < $string_1_length; $i++) {
                $longest_common_subsequence[$i] = array();
                for ($j = 0; $j < $string_2_length; $j++) {
                        $longest_common_subsequence[$i][$j] = 0;
                }
        }
 
        $largest_size = 0;
 
        for ($i = 0; $i < $string_1_length; $i++) {
                for ($j = 0; $j < $string_2_length; $j++) {
                        // Check every combination of characters
                        if ($string_1[$i] === $string_2[$j]) {
                                // These are the same in both strings
                                if ($i === 0 || $j === 0) {
                                        // It's the first character, so it's clearly only 1 character long
                                        $longest_common_subsequence[$i][$j] = 1;
                                } else {
                                        // It's one character longer than the string from the previous character
                                        $longest_common_subsequence[$i][$j] = $longest_common_subsequence[$i - 1][$j - 1] + 1;
                                }
 
                                if ($longest_common_subsequence[$i][$j] > $largest_size) {
                                        // Remember this as the largest
                                        $largest_size = $longest_common_subsequence[$i][$j];
                                        // Wipe any previous results
                                        $return       = array();
                                        // And then fall through to remember this new value
                                }
 
                                if ($longest_common_subsequence[$i][$j] === $largest_size) {
                                        // Remember the largest string(s)
                                        $return[] = substr($string_1, $i - $largest_size + 1, $largest_size);
                                }
                        }
                        // Else, $CSL should be set to 0, which it was already initialized to
                }
        }
 
        // Return the list of matches
        return $return;
}


function flashExplode ($stream) {
	$magic = substr($stream, 0, 3);

	if ($magic == "CWS") {
		$header = substr($stream, 4, 5);
		$content = substr($stream, 10);

		$uncompressed = gzinflate($content);
		return "FWS".$header.$uncompressed;
	} else
		return $stream;
}



function multiDecode($raw, $params =  array()) {
	$key = '';
	$rol = 0;
	$ror = 0;
	$tph = 0;
	$tp = 0;
	$la = 0;

	$not = 0;
	$zero = 0;
	$out = '';
	$data = $raw;

	if (isset($params['key_rol']))
		$ror = $params['key_rol'];
	if (isset($params['key']))
		$key = $params['key'];
	if (isset($params['key_tp']))
		$tp = $params['key_tp'];
	if (isset($params['key_tph']))
		$tph = $params['key_tph'];
	if (isset($params['key_not']))
		$not = $params['key_not'];
	if (isset($params['file']))
		$out = $params['out'];
	if (isset($params['key_zero']))
		$zero = $params['key_zero'];
	if (isset($params['key_la']))
		$zero = $params['key_la'];




	if ($key != '') {
		//echo "using XOR key $key\n";
		$data = xorString($data, hex2str($key), $zero);
	}

	if ($rol != 0 && $rol != '') {
		//echo "using ROL $rol\n";
		$data = cipherRol($data, $rol);
	}

	if ($ror != 0  && $ror != '') {
		//echo "using ROR $ror\n";
		$data = cipherRor($data, $ror);
	}

	if ($not != 0 && $not != '') {
		//echo "using bitwise not\n";
		$data = cipherNot($data);
	}

	if ($la != 0 && $la != '') {
		//echo "using lookahead not\n";
		$data = xorAheadString($data);
	}

	if ($tp != 0  && $tp != '') {
		//echo "using transposition decoder\n";
		$data = untranspose($data);
	}

	//if ($tph != 0  && $tph != '') {
		//echo "note first 512 bytes of EXE may be transpositioned\n";
	//}

	return $data;
}



function dump_pe($data, $filename, $tph = 0) {
	$file_headers =  array("MZ(.{1,150}?)This program" => "exe",
		"ZM(.{1,150}?)hTsip orrgmac" => "exe",
		"\xCA\xFE\xBA\xBE" => "macho",
		"\xCE\xFA\xED\xFE" => "macho",
		"\x7F\x45\x4C\x46" => "elf",
		"\x25\x50\x44\x46" => "pdf",
		"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" => "doc",
		"\x0A\x25\x25\x45\x4F\x46\x0A" => "eof",
		"\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A" => "eof",
		"\x0D\x25\x25\x45\x4F\x46\x0D" => "eof");

	$addresses = array();		
	$files = array();

	foreach($file_headers as $search => $ext) {
		preg_match_all("/$search/s", $data, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[0][0])) {
			foreach($match[0] as $matches0) {
				if (isset($matches0[1])) {
					$l = $matches0[1];
					if (! strstr($search, '?') && $ext == 'eof') {
						$ladd = preg_replace("/\\x./", '', $search);
						$l += strlen($ladd);
					}
					if ($l > 5) //skip plaintext full file extraction
						$addresses[$l] = array('loc' => $l, 'searchtype' => 'regex', 'ext' => $ext);
				}
			}

		}

	}

	//back into the right order
	ksort($addresses, SORT_NUMERIC);

	$last = '';
	$over = 0;
	foreach ($addresses as $loc => $hit) {
		if ($last != '') {
			$addresses[$last]['end'] = $loc;
			
		}
	
		if ($last != '' && $addresses[$last]['ext'] != 'eof' && $hit['ext'] == 'eof') {
		 	unset($addresses[$loc]);
			$over = 1;
		} else {
			$last = $loc;
			$over = 0;
		}
	}
	if ($over == 0) {
		$addresses[$last]['end'] = strlen($data);
	}


	$files = array();
	foreach ($addresses as $loc => $hit) {
		if (isset($hit['ext']) && $hit['ext'] != 'eof' && isset($hit['end']) && $loc != '' && $loc != 0) {
		
			//untranspose needed
			$dropfile = $filename."-".$loc.".".$hit['ext'];
			if ($hit['ext'] == "exe") $dropfile .= ".virus";

			$fp = fopen($dropfile, "w");
			$filedata = substr($data, $loc, $hit['end']-$loc);
			if ($tph == 1 && substr($filedata, 0, 2) == "ZM") {
				//echo "untransposing first 512 bytes at $loc\n";
				$filenew = untranspose(substr($filedata, 0, 512)).substr($filedata, 512);
				$filedata = $filenew;
			}
			$fmd5 = md5($filedata);
			fwrite($fp, $filedata);
			fclose($fp);
			$files[$loc] = array('len' => ($hit['end']-$loc), 'ext' => $hit['ext'], 'md5' => $fmd5, 'filename' => $filename."-".$loc.".".$hit['ext']);
			//echo "wrote ".($hit['end']-$loc)." bytes at $loc as type ".$hit['ext']." $fmd5\n";
		}
	}
	return $files;
}

function mtyara($filename, $signature_file) {
	global $global_yara_cmd;

	exec("$global_yara_cmd ".escapeshellarg($signature_file)." ".escapeshellarg($filename).' 2>&1', $out);

	$yara_result = array();
	$current_rule = '';
	$error = '';

	foreach ($out as $line) {
	
		if (substr($line, 0, 2) == "0x") {
			preg_match("/^0x([\da-fA-F]+):.(\w+): (.*)$/",$line, $matches);
			if (count($matches) < 3)
				break;
			list($all,$loc,$var, $string) = $matches;
			$loc_dec = hexdec($loc);
			$yara_result[$current_rule]['hits'][$loc] = array('loc_dec' => $loc_dec, 'var' => $var, 'string' => $string);
		} else if (preg_match("/^(\w+) \[(.*)\] (.*)$/",$line, $matches)) {
		
			list($all,$rule,$meta, $file) = $matches;
			$current_rule = $rule;

			$metadata = array();
			foreach (preg_split("/,(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))/",trim($meta)) as $item) {
				if (strpos($item, "=") === true) {
					list($name,$value) = explode('=', $item);
					$metadata[$name] = trim($value, '"');
				}
			}		
			$yara_result[$current_rule] = array('metadata' => $metadata, 'filename' => $file); 
		} else
			$error .= $line;


	}

	if ($error != '' || count($yara_result) == 0) return $error;

	return $yara_result;
}


function yara_wrapper($data) {
	global $global_yara_sig,$docdir;

	$tmp_file = "$docdir"."mwtcrtmyara-".uniqid();
	file_put_contents($tmp_file, $data);

	$result = mtyara($tmp_file, $global_yara_sig);
	unlink($tmp_file);
	return $result;

}

function yara_wrapper_file($file) {
	global $global_yara_sig;

	$result = mtyara($file, $global_yara_sig);

	return $result;

}



$docdir = "./";


function analyseDocx($path) {
	$results = array();
	
	$zip = new ZipArchive;
	if ($zip->open($path) === true) {
   
		for($i = 0; $i < $zip->numFiles; $i++) {

			$filename = $zip->getNameIndex($i);
			$fileinfo = pathinfo($filename);
			$newname = $path.".".$fileinfo['basename'];
			

			if (stristr($filename, '.bin')) {
				copy("zip://".$path."#".$filename,  $newname);

				//run it
				$result = analyseDoc($newname);

				if ($result['severity'] > 0)
					$results[$fileinfo['basename']] = $result;
				else
					unlink($newname);
			}		

		}
   		rmdir($tmpdir);
		$zip->close();
   
	}


	return $results;
}


function analyseDoc($filename) {
	global $global_engine, $global_true_keys, $global_yara_sig;

	$md5 = md5_file($filename);
	$sha1= sha1_file($filename);
	$sha256 = hash_file("sha256", $filename);
		
	logDebug("$md5 start processing");

	//echo getFileMetadata($filename);

	$sampleUpdate = array('hits' => 0, 'completed' => 0, 'is_malware' => 0, 
		'summary' => '', 'severity' => 0,
		'key' => '', 'key_len' => '', 'key_hash' => '', 'key_rol' => '', 'key_not' => '',
		'key_tp' => '', 'key_tph' => '', 'key_math' => '', 'key_la' => '', 'key_special' => '',
		'key_rank' => '', 'metadata'=> getFileMetadata($filename), 'has_exe' => 0,
		'md5' => $md5, 'sha1' => $sha1, 'sha256' => $sha256, 'yara' => array());
	$data = file_get_contents($filename);


	//check for MS Office xml format:
	if (substr($data, 0, 2) == "PK") {
		logDebug("$md5 is a PK Zip");
		$xmlembedded = analyseDocx($filename);

		foreach ($xmlembedded as $fname => $xresult) {
			if ($xresult['severity'] > 0) {
				$sampleUpdate['severity'] += $xresult['severity'];
				if ($xresult['has_exe'] == 1)
					$sampleUpdate['has_exe'] = 1;
				if (isset($xresult['yara']))
					$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;
				if ($xresult['is_malware'] == 1)
					$sampleUpdate['is_malware'] = 1;
				$summaries = explode("\n", $xresult['summary']);
				$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
				foreach ($summaries as $line) {
					if ($line != '')
						$sampleUpdate['summary'] .= "$fname.$line\n";
				}
				$sampleUpdate['completed'] = 1;
			}
		}
		if (isset($sampleUpdate['severity']) && $sampleUpdate['severity'] > 0)
			return $sampleUpdate;

	}


	//check for datastore in RTF
	if (stristr(substr($data, 0, 256),'\rt')) {
		preg_match_all("/([a-zA-Z0-9\x0a\x0d]{4096,})/s", $data, $match, PREG_OFFSET_CAPTURE);
		if (isset($match[1][0])) {
			$datastored = array();
			foreach($match[1] as $matches0) {
				if (isset($matches0[1])) {
					$l = $matches0[1];
					$len = strlen($matches0[0]);
					if ($len > 4096) {
						file_put_contents($filename."-datastore-".$l, hex2str($matches0[0]));

						$dresult = analyseDoc($filename."-datastore-".$l);

						if ($dresult['severity'] > 0)
							$datastored["datastore-".$l] = $dresult;
						else
							unlink($filename."-datastore-".$l);
					}
					
				}
			}
			foreach ($datastored  as $fname => $xresult) {
				if ($xresult['severity'] > 0) {
					$sampleUpdate['severity'] += $xresult['severity'];
					if ($xresult['has_exe'] == 1)
						$sampleUpdate['has_exe'] = 1;
					if ($xresult['is_malware'] == 1)
						$sampleUpdate['is_malware'] = 1;
					$summaries = explode("\n", $xresult['summary']);
					$sampleUpdate['summary'] .= "embedded.file $fname ".$xresult['md5']."\n";
					if (isset($xresult['yara']))
						$sampleUpdate['yara'] = array_merge($sampleUpdate['yara'],$xresult['yara']) ;

					foreach ($summaries as $line) {
						if ($line != '')
							$sampleUpdate['summary'] .= "$fname";
							if ( $xresult['key_rol'] != '' && $xresult['key_rol'] != '0' && !strstr($line, 'rol'))
								$line = str_replace(": ", ": rol".$xresult['key_rol'].".", $line);
							if ($xresult['key'] != '' && !strstr($line, 'xor'))
								$line = str_replace(": ", ": xor_0x".$xresult['key'].".", $line);

							$sampleUpdate['summary'] .= ".$line\n";
					}
					$sampleUpdate['completed'] = 1;
				}
			}
			//store datastore xor information

		}
	}


	$result = cryptoStat($data);
	$exploits = array();
	$hits = array();
	if (isset($result['exploits'])) {
		$exploits = $result['exploits'];
		unset($result['exploits']);
	}

	foreach ($sampleUpdate as $key => $value) {
		if ($value != "0" && $value != '')
			if (!isset($result[$key]) || $result[$key] == 0 || $result[$key] == 0)
				unset($result[$key]);
	}

	$result = array_merge($sampleUpdate,$result);

	$summary = $result['summary'];
	$severity = $result['severity'];

	$rol = 0;
	$not = 0;
	$la = 0;
	$tp = 0;
	$tph = 0;
	$math = 0;
	$has_exe = $result['has_exe'];


	foreach ($exploits as $l => $hit) {
		if (isset($hit['exploit']) && $hit['exploit'] != '') {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			if (preg_match("/exploit\./", $hit['hit_desc'], $match))
				$severity += 20;
			else
				$severity += 2;
			
		} else {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;
			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


	}
	
	if ( $has_exe == 1) { //plaintext
		$result['key'] = '';
		$result['key_len'] = 0;
		$result['key_occ'] = 0;
		$result['key_hash'] = '';
		$result['key_rank'] = 0;
		$result['key_entropy'] = '';


	} else if ($result['key'] == "00") {
		//echo "<P>key 00 recheck</P>\n";
		$xorexp = scanXORByte($data);
		$xor = $xorexp['xor'];
		//var_dump($xorexp);
		unset($xorexp['xor']);
		if ($xor != '') {
			$result['key'] = $xor;
			$result['key_len'] = 1;
			$result['key_occ'] = 0;
			$result['key_entropy'] = 100.0;
			$result['key_zero'] = 1;

			foreach ($xorexp as $l => $hit) {
				$hit['parent_md5'] = $md5;
				$hit['parent_sha256'] = $sha256;
				$hits[$hit['exploit_loc']] =  $hit;
				$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
				$severity += 10;

				if (preg_match("/\.rol(\d+)/", $hit['hit_desc'], $match))
					$rol = $match[1];
				if (preg_match("/\.not/", $hit['hit_desc'], $match))
					$not = 1;
				if (preg_match("/\.xorla/", $hit['hit_desc'], $match))
					$la = 1;

				if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
					if (preg_match("/This program/", $hit['hit_desc'], $match))
						$tph = 1;
					else
						$tp = 1;
				}

				$has_exe = 1;
			}
		} else {
			$result['key'] = '';
			$result['key_len'] = 0;
			$result['key_occ'] = 0;
			$result['key_entropy'] = '';
			if (count($hits) == 0)
				$result['is_malware'] = 0;
			
		}


	} else if (isset($result['key_len'])  && $result['key_len'] > 0) {
		$malware = scanFile($data, $result['key']);

		if (count($malware) <= 1) {
			
			foreach ($global_true_keys as $tkey) {
				$lkey = $result['key'];
			
				if (strlen($lkey) > 512)
					$lkey = keyPivot($result['key'], 256);
				$skey = key_align($lkey, $tkey);
				if ($skey != '') {
					$m2 = scanFile($data, $skey);
					if (count($m2) > 1) {
						$result['key'] = $skey;
						$result['key_len'] = strlen($skey)/2;
						$malware = $m2;
						break;
					}
				}
			}
		}


		foreach ($malware as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


	}

	if ($result['key_len'] == 1024 && $has_exe != 1) {
		$xorexp = scanXORByte($data);
		$xor = $xorexp['xor'];
		//var_dump($xorexp);
		unset($xorexp['xor']);
		if ($xor != '') {
			$result['key'] = $xor;
			$result['key_len'] = 1;
			$result['key_occ'] = 0;
			$result['key_entropy'] = 100.0;
			$result['key_zero'] = 1;

			foreach ($xorexp as $l => $hit) {
				$hit['parent_md5'] = $md5;
				$hit['parent_sha256'] = $sha256;
				$hits[$hit['exploit_loc']] =  $hit;
				$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
				$severity += 10;

				if (preg_match("/\.rol(\d+)/", $hit['hit_desc'], $match))
					$rol = $match[1];
				if (preg_match("/\.not/", $hit['hit_desc'], $match))
					$not = 1;
				if (preg_match("/\.xorla/", $hit['hit_desc'], $match))
					$la = 1;
	
				if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
					if (preg_match("/This program/", $hit['hit_desc'], $match))
						$tph = 1;
					else
						$tp = 1;
				}

				$has_exe = 1;
			}
		} else {
			$result['key'] = '';
			$result['key_len'] = 0;
			$result['key_occ'] = 0;
			$result['key_entropy'] = '';
			if (count($hits) == 0)
				$result['is_malware'] = 0;
			
		}

	}




	if ($result['is_malware'] == 1 && $severity == 0) 
		$severity = 1;

	$result['has_exe'] = $has_exe;

	//start start of entropy area
	if ($result['has_exe'] == 0 && isset($result['key_blocks'])) {
		//echo "trigger special case for dropped document uses a different key then exe\n";
		//echo $result['key_blocks']."\n";
		$check = strpos($result['key_blocks'],'11111111111');
		$checkFile = strlen($result['key_blocks']);
		$magicSize = number_format(($checkFile - $check) * 0.25 * 1024, 0, '.', '');
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "looking at ".($check*1024)." bytes+$magicSize\n";
		$subres = cryptoStat(substr($data, $check*1024, $magicSize));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}


	//check end of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks']) ) {
		//echo "trigger special case for dropped document uses a different key then exe, inverse\n";
		//echo $result['key_blocks']."\n";
		$checkFile = strlen($result['key_blocks']);
		$magicSize = number_format($checkFile * 0.14 * 1024, 0, '.', '');
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "-$magicSize\n";
		$subres = cryptoStat(substr($data, -$magicSize));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;
			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}


	//check middle of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks'])) {
		//echo "trigger special case for dropped document uses a different key then exe, middle\n";
		//echo $result['key_blocks']."\n";
		$checkFile = number_format(strlen($result['key_blocks']) / 2 * 1024, 0, '.', ''); ;
		$magicSize = $checkFile / 2;
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "$checkFile -$magicSize\n";
		$subres = cryptoStat(substr($data, $checkFile-$magicSize, $magicSize*2));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;
			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}

	//check near the end of file
	if ($result['has_exe'] == 0  && isset($result['key_blocks'])) {
		//echo "trigger special case for dropped document uses a different key then exe, inverse\n";
		//echo $result['key_blocks']."\n";
		$checkFile = strlen($result['key_blocks']);
		$magicSize = number_format($checkFile * 0.14 * 1024, 0, '.', '');
		if ($magicSize > 64000) $magicSize = 64000;
		//echo "-$magicSize\n";
		//echo (-$magicSize*3)." $magicSize\n";
		$subres = cryptoStat(substr($data, -$magicSize*3, $magicSize));
		//var_dump($subres);
		$submalw = scanFile($data, $subres['key']);

		//var_dump($submalw);


		foreach ($submalw as $l => $hit) {
			$hit['parent_md5'] = $md5;
			$hit['parent_sha256'] = $sha256;
			$hits[$hit['exploit_loc']] =  $hit;
			$summary .= $hit['exploit_loc'].": ".$hit['hit_desc']."\n";
			$severity += 10;

			if (preg_match("/^rol(\d+)/", $hit['hit_desc'], $match))
				$rol = $match[1];
			if (preg_match("/^not/", $hit['hit_desc'], $match))
				$not = 1;
			if (preg_match("/^xorla/", $hit['hit_desc'], $match))
				$la = 1;

			if (preg_match("/transposition cipher/", $hit['hit_desc'], $match)) {
				if (preg_match("/This program/", $hit['hit_desc'], $match))
					$tph = 1;
				else
					$tp = 1;
			}

			$has_exe = 1;
		}


		if ($has_exe == 1) {
			$result['key'] = $subres['key'];
			$result['key_len'] = $subres['key_len'];
			$result['key_occ'] = $subres['key_occ'];
			$result['key_rank'] = $subres['key_rank'];
			$result['key_entropy'] = $subres['key_entropy'];
			$result['h_dispersion'] = $subres['h_dispersion'];
			$result['h_distribution'] = $subres['h_distribution'];
			if (isset($subres['key_zero']))
				$result['key_zero'] = $subres['key_zero'];
			$result['key_hash'] = $subres['key_hash'];
			$result['is_malware'] = 1;
			$result['has_exe'] = 1;
		}

	}





	$result['completed'] = 1;
	$result['summary'] = $summary;
	$result['severity'] = $severity;
	$result['key_rol'] = $rol;
	$result['key_not'] = $not;
	$result['key_tp'] = $tp;
	$result['key_la'] = $la;
	$result['key_tph'] = $tph;
	$result['key_math'] = $math;
	$result['has_exe'] = $has_exe;
	$result['hits'] = $hits;

	
	//yara original file
	if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
		$yhits = yara_wrapper_file($filename);
		foreach ($yhits as $k => $v) {
			array_push($result['yara'], $k);
		}
	}


	//extract embedded files
	if ($result['has_exe'] > 0) {
		$decoded = multiDecode($data, $result);
		$files = dump_pe($decoded, $filename, $tph);

		foreach ($files as $loc => $filemeta) {
			$result['summary'] .= "dropped.file ".$filemeta['ext']." ".$filemeta['md5']." / ".$filemeta['len']." bytes / @ ".$loc."\n";

			//yara dropped files
			if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
				$yhits = yara_wrapper_file($filemeta['filename']);
				foreach ($yhits as $k => $v) {
					array_push($result['yara'], $k);
				}
			}


		}


		//yara xored section
		if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
			$yhits = yara_wrapper($decoded);
			foreach ($yhits as $k => $v) {
				array_push($result['yara'], $k);
			}
		}


	}

	$result['yara'] = array_unique($result['yara']);


	return $result;
}



set_time_limit(0);





if (!isset($cryptam_executable_sigs)) {
	echo "ERROR: Signatures not found. cryptam-sig.php missing or corrupt.\n";
	exit(0);
}



if (!isset($argv[1])) {
	echo "Specify a file or directory.\n";
	exit(0);
}

date_default_timezone_set('America/Toronto');

$options = getopt("y:v", array("yara:","yarasig:","version","info"));

if (isset($options['y']))
	$global_yara_sig = $options['y'];
if (isset($options['yarasig']))
	$global_yara_sig = $options['yarasig'];
if (isset($options['yara']))
	$global_yara_cmd = $options['yaracmd'];
if (isset($options['version']) || isset($options['v']) || isset($options['info'])) {
	echo "cryptam.php <-y yarasig> <file or dir>\n";
	if (!isset($global_engine) ) {
		echo "ERROR: Signatures not found.\n";
		exit(1);
	} 
	echo "Detection engine: $global_engine\n";
	echo "Embedded executable signatures: ".count($cryptam_executable_sigs)."\n";
	echo "Exploit signatures: ".count($cryptam_plaintext_sigs)."\n";
}

$file = array();
$dir = array();
$opt = array();


function malware_analysis ($f) {

	$result = analyseDoc($f);

	if (count($opt) > 0) {
		foreach ($opt as $o => $y) {
			if (isset($result[$o])) {
				if ($argc > 2)
					echo $o."=";
				if (!is_array($result[$o]))
					echo $result[$o]."\n";
				else {
					foreach ($result[$o] as $item) {
						echo "$item\n";
					}
				}

			}
		}
	} else {
		if (isset($result['h_distribution'])) unset($result['h_distribution']);
		if (isset($result['h_dispersion'])) unset($result['h_dispersion']);
		
		$json_res = json_encode($result);
		echo $json_res;
	}
}



function logdebug($string) {
	//echo $string."\n";
}
function logverbose($string) {
	//echo $string."\n";
}




?>
