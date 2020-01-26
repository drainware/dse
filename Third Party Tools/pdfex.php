<?PHP
/*
 * v2.05
 * pdfex.php: MalwareTracker.com PDFExaminer - command line script
 * Main script to call for command line usage: 
 * php pdfex.php <filename> [data element to display/defaults to
 * all when blank]
 */

//yara executable and signatures
$global_yara_cmd = '/opt/local/bin/yara -s -m';
$global_yara_sig = '';


ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_COMPILE_ERROR|E_ERROR|E_CORE_ERROR);
date_default_timezone_set('America/Toronto');



ini_set('pcre.backtrack_limit', 10000000);
ini_set('pcre.recursion_limit', 10000000);
ini_set('memory_limit', '256M');
set_time_limit(0);
$global_test = 0; //debug mode


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



/*

if (!isset($argv[1])) {
	echo "Specify a file or directory.\n";
	exit(0);
}


//accept a file as input
if (is_file($argv[1])) {
	$result = pdfSlice(file_get_contents($argv[1]));
	print_r($result);
}

function logdebug($string) {
	echo $string."\n";
}
function logverbose($string) {
	//echo $string."\n";
}
*/


$encodingMethods = array('PA' => 'PDF ASCIIHexDecode', 'PL' => 'PDF LZWDecode', 'P8' => 'PDF ASCII85Decode',
	'PR' => 'PDF RunLengthDecode', 'PF' => 'PDF FlateDecode', 'pf' => 'PDF FlateDecode2', 'OC' => '', 
	'ES' => 'JavaScript Escaped', 'JA' => 'JavaScript Ascii codes', 'UC' => 'Unicode',
	'RH' => 'JavaScript Hex codes', 'CF' => 'JavaScript fromCharCode', 'OC' => 'PDF Octal codes',
	'oc' => 'PDF Octal codes2', 'pa' => 'PDF ASCIIHexDecode2', 'JB' => 'JavaScript in Annotation Block',
	'JR' => 'JavaScript in Block', 'CR' => 'PDF Standard Encryption',);







function pdfDecrypt($message, $key, $vector) {
    return mcrypt_decrypt(
        MCRYPT_RIJNDAEL_128, 
        $key, 
        $message, 
        MCRYPT_MODE_CBC, 
        $vector
    );
}



function pdfDecryptRC4($message, $key, $ishex = 0) {
	return rc4($key, $message, $ishex);
}


function rc4 ($pwd, $data, $ispwdHex = 0)
		{
			if ($ispwdHex)
				$pwd = @pack('H*', $pwd); // valid input, please!

			$key[] = '';
			$box[] = '';
			$cipher = '';

			$pwd_length = strlen($pwd);
			$data_length = strlen($data);

			for ($i = 0; $i < 256; $i++)
			{
				$key[$i] = ord($pwd[$i % $pwd_length]);
				$box[$i] = $i;
			}
			for ($j = $i = 0; $i < 256; $i++)
			{
				$j = ($j + $box[$i] + $key[$i]) % 256;
				$tmp = $box[$i];
				$box[$i] = $box[$j];
				$box[$j] = $tmp;
			}
			for ($a = $j = $i = 0; $i < $data_length; $i++)
			{
				$a = ($a + 1) % 256;
				$j = ($j + $box[$a]) % 256;
				$tmp = $box[$a];
				$box[$a] = $box[$j];
				$box[$j] = $tmp;
				$k = $box[(($box[$a] + $box[$j]) % 256)];
				$cipher .= chr(ord($data[$i]) ^ $k);
			}
			return $cipher;
		}



function lowOrder($data) {
	$new = '';
	for ($i = strlen($data)-2; $i>=0; $i-=2) {
		$new .= $data[$i].$data[$i+1];
	}
	return $new;
}


function flashExplode ($stream) {

	$magic = substr($stream, 0, 3);

	if ($magic == "CWS") {
		$header = substr($stream, 4, 5);
		$content = substr($stream, 10);

		//echo strlen($magic)."\n";
		//echo "magic=$magic\n";
		//echo strlen($header)."\n";
		//echo "header=$header\n";
		$uncompressed = gzinflate($content);
		return "FWS".$header.$uncompressed;
	} else
		return $stream;

}



function asciihexdecode($hex)
{
	$bin = '';
	for ($i = 0; $i < strlen($hex)-1; $i++) {
		if (ctype_alnum($hex[$i]) &&  ctype_alnum($hex[$i+1])) {
			$n = $hex[$i].$hex[$i+1];
			$bin .= chr(hexdec($n));
			$i++;
 		} else {
		//do nothing
		}
	}
	return $bin;
}

function pdfhex($hex)
{
	$str = '';
	for ($i = 0; $i < strlen($hex); $i++) {
		if ($i+2 <= strlen($hex) && $hex[$i] == '#' && ctype_alnum($hex[$i+1]) &&  ctype_alnum($hex[$i+2])) {
			$n = $hex[$i+1].$hex[$i+2];
			$str .= chr(hexdec($n));
			$i+=2;
 		} else {
			$str .= $hex[$i];
		}

	}

  return $str;
}

function octal_decode($oct) {
		$dec = '';
		for ($i = 0; $i < strlen($oct); $i++) {
			if ($oct[$i] == '\\') {
				$n = '';
				$i++;
				for (; $i < strlen($oct); $i++) {
					if (is_numeric($oct[$i]))
						$n .= $oct[$i];
					else {
						$i--;
						break;
					}
				}
				$dec .= chr(octdec($n));
 			} else {
				$dec .= $oct[$i];
			}
		}
	return $dec;
}






function flatedecode($data) {

	$errlev = error_reporting();
	error_reporting(0);
	$out = gzinflate($data);
	error_reporting($errlev);

	return $out;
}



function lzw_decode($data) {
	$lz = new LZW();
	$d = $lz->decode($data);
	return $d;
}


function ascii85_decode($data) {
    $output = '';

    //get rid of the whitespaces
    $whiteSpace = array("\x00", "\x09", "\x0A", "\x0C", "\x0D", "\x20");
    $data = str_replace($whiteSpace, '', $data);
    
    $data = substr($data, 0, (strlen($data) - 2));
    $dataLength = strlen($data);

    for ($i = 0; $i < $dataLength; $i += 5) {
        $b = 0;

        if (substr($data, $i, 1) == "z") {
            $i -= 4;
            $output .= pack("N", 0);
            continue;
        }

        $c = substr($data, $i, 5);

        if(strlen($c) < 5) {
            //partial chunk
            break;
        }

        $c = unpack('C5', $c);
        $value = 0;

        for ($j = 1; $j <= 5; $j++) {
            $value += (($c[$j] - 33) * pow(85, (5 - $j)));
        }

        $output .= pack("N", $value);
    }

    //decode partial
    if ($i < $dataLength) {
        $value = 0;
        $chunk = substr($data, $i);
        $partialLength = strlen($chunk);

        //pad the rest of the chunk with u's 
        //until the lenght of the chunk is 5
        for ($j = 0; $j < (5 - $partialLength); $j++) {
            $chunk .= 'u';
        }

        $c = unpack('C5', $chunk);

        for ($j = 1; $j <= 5; $j++) {
            $value += (($c[$j] - 33) * pow(85, (5 - $j)));
        }
        
        $foo = pack("N", $value);
        $output .= substr($foo, 0, ($partialLength - 1));
    }

    return $output;
}

function runlengthdecode($data) {
    $dataLength = strlen($data);
    $output = '';
    $i = 0;

    while($i < $dataLength) {
        $byteValue = ord($data[$i]);

        //EOD byte
        if ($byteValue == 128) {
            break;
        }

        if ($byteValue < 128) {
            $output .= substr($data, $i + 1, ($byteValue + 1));
            $i += $byteValue + 2;
        }

        if ($byteValue > 128) {
            $numOfTimesToCopy = 257 - $byteValue;
            $copyValue = $data[$i + 1];

            for($j = 0; $j < $numOfTimesToCopy; $j++) {
                $output .= $copyValue;
            }

            $i += 2;
        }
    }
    return $output;
}

function strhex($string) {

    $hex = '';
    $len = strlen($string);
   
    for ($i = 0; $i < $len; $i++) {
        
        $hex .= str_pad(dechex(ord($string[$i])), 2, 0, STR_PAD_LEFT);
   
    }
       
    return $hex;
    
}


function decryptObj(&$document, &$object, $key, $stream) {


	if ($key != '') {
		$object['key_long']  = $key.$object['decrypt_part'];
		$object['key'] = md5(hex2bin($object['key_long']));
			

		if ($document['r'] == 5) {
			$t = pdfDecrypt(
				substr($stream, 16),
				hex2bin($key),
				substr($stream, 0, 16));
				//remove padding - aes
			//echo "result=$t==\n";
			$last = ord(substr($t, -1));
			//echo "checking for padding of $last\n";
			$padding = substr($t, -$last);
			//echo "padding is ".strhex($padding)."\n";
			$pad_fail = 0;
			for($i = 0; $i < $last; $i++) {
				if ($padding[$i] != chr($last)) {
					$pad_fail = 1;
					break;
				}
			}

			if ($pad_fail == 0) {
				//echo "trimming padding\n";
				$t = substr($t, 0, (strlen($t)-$last) );
			}

		} else if ($document['r'] == 4) {
			$t = pdfDecrypt(
				substr($stream, 16),
				hex2bin($object['key']),
				substr($stream, 0, 16));
				//remove padding - aes
			$last = ord(substr($t, -1));
			//echo "checking for padding of $last\n";
			$padding = substr($t, -$last);
			//echo "padding is ".strhex($padding)."\n";
			$pad_fail = 0;
			for($i = 0; $i < $last; $i++) {
				if ($padding[$i] != chr($last)) {
					$pad_fail = 1;
					break;
				}
			}

			if ($pad_fail == 0) {
				//echo "trimming padding\n";
				$t = substr($t, 0, (strlen($t)-$last) );
			}

		} else {
			if ($document['v'] == 1){
				//$object['decrypt_part'] = "0a00000000";
				//$object['key_long']  = $key.$object['decrypt_part'];
				//$object['key'] = md5(hex2bin($object['key_long']));
				$object['key'] = substr($object['key'], 0, 20);
			}
			if ($document['v'] == 3) {
				$object['obj_hex'] = pdfxor(pdfhex2str($object['obj_hex']),  pdfhex2str('3569AC'));
				$object['gen_hex'] = pdfxor(pdfhex2str($object['gen_hex']),  pdfhex2str('CA96'));

				//echo "tyler ".$object['obj_hex']." ".$object['gen_hex']."\n";
				$object['decrypt_part'] = lowOrder($object['obj_hex']).lowOrder($object['gen_hex']);
				if ($document['v'] >= 3) {
					$object['decrypt_part'] .= "73416C54";
				}
				$object['key_long']  = $key.$object['decrypt_part'];
				$object['key'] = md5(hex2bin($object['key_long']));

			}
			//echo $object['object']." using key ".$object['key']."\n";
			$t = pdfDecryptRC4($stream,$object['key'], 1);
			//echo "rc4 ".strlen($t)." ".$t."\n";
		}
	} else 
		$t = $stream;
	return $t;
}

function pdfhex2str($hex)
{
	$str = '';
  for($i=0;$i<strlen($hex);$i+=2)
  {
    $str.=chr(hexdec(substr($hex,$i,2)));
  }
  return $str;
}





function pdfxor($InputString, $KeyPhrase){
 
    $KeyPhraseLength = strlen($KeyPhrase);
 
    // Loop trough input string
    for ($i = 0; $i < strlen($InputString); $i++){
 
        // Get key phrase character position
        $rPos = $i % $KeyPhraseLength;
 
        // Magic happens here:
        $r = ord($InputString[$i]) ^ ord($KeyPhrase[$rPos]);
 
        // Replace characters
        $InputString[$i] = chr($r);
    }
 
    return $InputString;
}

function unliteral($oct) {
		$dec = '';
		for ($i = 0; $i < strlen($oct); $i++) {
			if ($oct[$i] == '\\') {
				if ($oct[$i+1] == 'n') {
					$dec .= chr(hexdec("0a"));
					$i+= 1;
				} else if ($oct[$i+1] == 'r') {
					$dec .= chr(hexdec("0d"));
					$i+= 1;
				} else if ($oct[$i+1] == 't') {
					$dec .= chr(hexdec("09"));
					$i+= 1;
				} else if ($oct[$i+1] == 'b') {
					$dec .= chr(hexdec("08"));
					$i+= 1;
				} else if ($oct[$i+1] == 'f') {
					$dec .= chr(hexdec("0c"));
					$i+= 1;
				} else if ($oct[$i+1] == '(') {
					$dec .= chr(hexdec("28"));
					$i+= 1;
				} else if ($oct[$i+1] == ')') {
					$dec .= chr(hexdec("29"));
					$i+= 1;
				} else if ($oct[$i+1] == '\\') {
					$dec .= chr(hexdec("5c"));
					$i+= 1;
				} else if (isset($oct[$i+3]) && preg_match('/^[0-7]$/', $oct[$i+1].$oct[$i+2].$oct[$i+3]) === true ) {
					$dec .= chr(octdec($oct[$i+1].$oct[$i+2].$oct[$i+3]));
					$i+= 3;
				} else if (isset($oct[$i+2]) && preg_match('/^[0-7]$/', $oct[$i+1].$oct[$i+2]) === true ) {
					$dec .= chr(octdec($oct[$i+1].$oct[$i+2]));
					$i+= 2;
				} else if (isset($oct[$i+1]) && preg_match('/^[0-7]$/', $oct[$i+1]) === true ) {
					$dec .= chr(octdec($oct[$i+1]));
					$i+= 1;
				} else {
					$dec .= $oct[$i];
				}
 			} else {
				$dec .= $oct[$i];
			}
		}
	return $dec;
}



function pdfSlice($data) {
	global $global_test, $literalEncodings, $global_userpass;
	$key = '';

	$master_block_encoding = '';
	$block_encoding = '';

	$result = array('document' => array());
	$result['document']['v'] = "0";


	logDebug("crypto check");

	if (preg_match("/\/AuthEvent\/DocOpen\/CFM\/AESV2/si", $data) || preg_match("/\/Encrypt\s+/s", $data)) {


		//find Encryption defns
		if (preg_match("/\/Encrypt (\d+)\D+(\d+)\D+R/si", $data,$matches)) {
			$result['document']['encrypt_obj'] = $matches[1];
			$result['document']['encrypt_gen'] = $matches[2];
			//echo "Looking for encryption obj ".$result['document']['encrypt_obj']." ".$result['document']['encrypt_gen']."\n";

			preg_match_all("/(\x0a|\x0d|\x20)".$result['document']['encrypt_obj']."[^\d]{1,3}".$result['document']['encrypt_gen']."[^\d]{1,3}obj(.+?)endobj/si", $data, $matches0, PREG_OFFSET_CAPTURE);
			
			//print_r($matches0);
			if (isset($matches0[0])) {
				$ordered = array();
				for($j = 0; $j< count($matches0[0]); $j++) {
					$ordered[$matches0[2][$j][1]] = array();
					for($i = 1; $i< count($matches0); $i++) {
						$ordered[$matches0[2][$j][1]][$i] = $matches0[$i][$j][0];
					}
				}
			}
			//print_r($ordered);
			$encrypt_block = end($ordered);
			$encrypt_block = $encrypt_block[2];
			//print_r($encrypt_block);
			
		}

		if ( !isset($encrypt_block) ) {
			preg_match("/\/Encrypt(.*?)(endobj|$)/si", $data,$matches);
			if (isset($matches[1]))
				$encrypt_block = $matches[1];
		}

		if ( !isset($encrypt_block) )
			$encrypt_block = $data;

		$encrypted = 1;	
		$result['document']['encrypted'] = 1;

		$result['document']['padding'] = '28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A'; //standard padding

		$result['document']['u']  = "00000000000000000000000000000000";
		if (isset ($global_userpass) && $global_userpass != '')
			$result['document']['u']  = strhex($global_userpass);

		$result['document']['o'] = "";
		$result['document']['id'] = "";

		if (preg_match_all("/\/ID[^\[]{0,5}\[\s*<(.*?)>/si", $data, $matchi)) {
			//print_r($matchi);
			$last = count($matchi[1])-1;
			if ($last < 0) $last = 0;
			$result['document']['id'] = $matchi[1][$last];

		} else if (preg_match_all("/\/ID[^\[]{0,5}\[\s*\((.*?)\)/si", $data, $matchi)) {
			//print_r($matchi);
			$last = count($matchi[1])-1;
			if ($last < 0) $last = 0;
			$result['document']['id'] = strhex(unliteral($matchi[1][$last]));

		}
		if (preg_match("/\/O[^\(]{0,5}\((.{32,64}?)\)/si", $encrypt_block, $matcho))
			$result['document']['o'] = strhex($matcho[1]);
		else if (preg_match("/\/O[^\<]{0,5}\<(.{64}?)\>/si", $encrypt_block, $matcho))
			$result['document']['o'] = $matcho[1];


		if ($result['document']['o'] == "" && preg_match("/trailer.{1,400}\/O[^\<]{0,5}\<(.{32,64}?)\>/si", $data, $matcho))
			$result['document']['o'] = $matcho[1];
		$result['document']['o_orig'] = $result['document']['o'];
		if (strlen($result['document']['o']) > 64) { //fix escaped things
			$result['document']['o'] = strhex(unliteral(hex2str($result['document']['o'])));
			//$result['document']['o'] = str_replace("5c72", "0d", $result['document']['o']);
			//$result['document']['o'] = str_replace("5c5c", "[block]", $result['document']['o']);
			//$result['document']['o'] = str_replace("5c", "", $result['document']['o']);
			//$result['document']['o'] = str_replace("[block]", "5c", $result['document']['o']);

		}

		$result['document']['key_length'] = 128;
		if (preg_match("/\/Length\s+(\d{1,4})\D/si",$encrypt_block, $matchl))
			$result['document']['key_length'] = $matchl[1];
		if ($result['document']['key_length'] <= 16)
			$result['document']['key_length'] *= 8;

		$result['document']['r'] = 1; //version
		if (preg_match("/\/R (\d{1})\D/si",$encrypt_block, $matchr))
			$result['document']['r'] = $matchr[1]; //version 1-4

		$result['document']['v'] = 4; //version
		if (preg_match("/\/V (\d{1})\D/si", $encrypt_block, $matchv))
			$result['document']['v'] = $matchv[1]; //version 1-4

		if (preg_match("/\/P ([0-9-]*)/si", $encrypt_block, $matchp))
			$result['document']['p'] = $matchp[1]; //permission - 32 bit
		
		if ($result['document']['r'] <= 2) $result['document']['key_length'] = 40;


		//r=5 AESV3 (AES-256) 2011 12 15
		if ($result['document']['r'] == 5) {
			$result['document']['key_length'] = 256;
			//StrF-EFF

			//O is 48 bytes
			if (preg_match("/\/O[^\(]{0,5}\((.{48,132}?)\)/si", $encrypt_block, $matcho))
				$result['document']['o'] = strhex($matcho[1]);
			else if (preg_match("/\/O[^\<]{0,5}\<(.{96,164}?)\>/si", $encrypt_block, $matcho))
				$result['document']['o'] = $matcho[1];

			if (strlen($result['document']['o']) > 96)  //fix escaped things
				$result['document']['o'] = strhex(unliteral(hex2str($result['document']['o'])));

			if (strlen($result['document']['o']) > 96)
				$result['document']['o'] = substr($result['document']['o'], 0, 96);


			if (preg_match("/\/U[\s]{0,5}\((.{48,132}?)\)/si", $encrypt_block, $matcho))
				$result['document']['u'] = strhex($matcho[1]);
			else if (preg_match("/\/U[\s]{0,5}\<(.{96,164}?)\>/si", $encrypt_block, $matcho))
				$result['document']['u'] = $matcho[1];
			if (strlen($result['document']['u']) > 96)  //fix escaped things
				$result['document']['u'] = strhex(unliteral(hex2str($result['document']['u'])));

			if (strlen($result['document']['u']) > 96)
				$result['document']['u'] = substr($result['document']['u'], 0, 96);

			$result['document']['oe'] = "";
			$result['document']['ue'] = "";
			$result['document']['perms'] = "";
		
			if (preg_match("/\/OE[^\(]{0,5}\((.{32,64}?)\)/si", $encrypt_block, $matcho))
				$result['document']['oe'] = strhex($matcho[1]);
			else if (preg_match("/\/OE[^\<]{0,5}\<(.{64}?)\>/si", $encrypt_block, $matcho))
				$result['document']['oe'] = $matcho[1];
			if (strlen($result['document']['oe']) > 64)  //fix escaped things
				$result['document']['oe'] = strhex(unliteral(hex2str($result['document']['oe'])));


			if (preg_match("/\/UE[^\(]{0,5}\((.{32,64}?)\)/si", $encrypt_block, $matcho))
				$result['document']['ue'] = strhex($matcho[1]);
			else if (preg_match("/\/UE[^\<]{0,5}\<(.{64}?)\>/si", $encrypt_block, $matcho))
				$result['document']['ue'] = $matcho[1];
			if (strlen($result['document']['ue']) > 64)  //fix escaped things
				$result['document']['ue'] = strhex(unliteral(hex2str($result['document']['ue'])));

			if (preg_match("/\/Perms[^\(]{0,5}\((.{16,32}?)\)/si", $encrypt_block, $matcho))
				$result['document']['perms'] = strhex($matcho[1]);
			else if (preg_match("/\/Perms[^\<]{0,5}\<(.{32}?)\>/si", $encrypt_block, $matcho))
				$result['document']['perms'] = $matcho[1];
			if (strlen($result['document']['perms']) > 32)  //fix escaped things
				$result['document']['perms'] = strhex(unliteral(hex2str($result['document']['perms'])));


			//Algorithm 3.2a proposed ISO 32000-2
/*To understand the algorithm below, it is necessary to treat the O and U strings in the Encrypt dictionary as made up of three sections. The first 32 bytes are a hash value (explained below). The next 8 bytes are called the Validation Salt. The final 8 bytes are called the Key Salt.*/


			$result['document']['password'] = '';


/*Compute an intermediate user key by computing the SHA-256 hash of the UTF-8 password concatenated with the 8 bytes of user Key Salt. The 32-byte result is the key used to decrypt the 32-byte UE string using AES-256 in CBC mode with no padding and an initialization vector of zero. The 32-byte result is the file encryption key.*/

			//echo "UE: ".$result['document']['ue']."\n";
			//echo "user key salt:".substr($result['document']['u'], 80, 16)."\n";

			$result['document']['ue_key']= hash('sha256', hex2bin($result['document']['password'].substr($result['document']['u'], 80, 16)));

			$result['document']['key'] = strhex(mcrypt_decrypt(MCRYPT_RIJNDAEL_128,hex2bin($result['document']['ue_key']), hex2bin($result['document']['ue']), MCRYPT_MODE_CBC), ''); //AES256

			//echo "ukey: ".$result['document']['key']."\n"; 

/*
Decrypt the 16-byte Perms string using AES-256 in ECB mode with an initialization vector of zero and the file encryption key as the key. Verify that bytes 9-11 of the result are the characters 'a', 'd', 'b'. Bytes 0-3 of the decrypted Perms entry, treated as a little-endian integer, are the user permissions. They should match the value in the P key.*/

			//echo "check perms: ".$result['document']['perms']."\n";

			$result['document']['test2'] = strhex(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, hex2bin($result['document']['key']), hex2bin(substr($result['document']['perms'], 0, 32)), MCRYPT_MODE_ECB, ''));

			if (substr(hex2bin($result['document']['test2']), 9,3) == "abd")
				$result['document']['aesv3'] = 1;
			else
				$result['document']['aesv3'] = 0;


			$key = $result['document']['key'];
		} else {

			//Algorithm 3.2





			//ISO 32000-1 2008 7.6.3.3 Encryption Key Algorithm 2, step a:
			$trimmed = rtrim($result['document']['u'], "0");
			//echo "trimmed ".strlen($trimmed)."\n";
			if (strlen($trimmed) % 2 == 1)
				$trimmed .= "0";
			//echo "trimmed ".strlen($trimmed)."\n";
			$result['document']['password'] = str_pad($trimmed, 64,  $result['document']['padding'], STR_PAD_RIGHT);

			//checks
			//echo "O check ".strlen($result['document']['o'])."\n";
			//echo "u check ".strlen($result['document']['u'])."\n";
			//echo "p check ".strlen($result['document']['password'])."\n";

	
			//step b
			//echo "step b ".$result['document']['password']."\n";
			$hashbuilder = $result['document']['password'];

			//step c
			$hashbuilder .= $result['document']['o'];
			//echo "step c ".$result['document']['o']."\n";

			//step d Convert the integer value of the P entry to a 32-bit unsigned binary number
			//and pass these bytes to the MD5 hash function, low-order byte first
	

			if ($result['document']['p'] < 0)
				$permissions = pow(2, 32) + ($result['document']['p']);
			else
				$permissions = $result['document']['p'];

			$result['document']['p_hexh'] = str_pad(dechex( pow(2, 32)- pow(2, 32)+$permissions), 8, 0, STR_PAD_LEFT);
			$result['document']['p_hex'] = lowOrder($result['document']['p_hexh']);
			$result['document']['p_raw'] = $permissions;
			$result['document']['p_max'] = pow(2, 32);
			$result['document']['p_check'] = hexdec($result['document']['p_hexh']);

			$hashbuilder .= $result['document']['p_hex'];

			//echo "step c ".lowOrder(dechex($permissions))."\n";

			//step e add id
			//echo "step e ".$result['document']['id']."\n";
			$hashbuilder .= $result['document']['id'];

			//step f revision 4 or greater) If document metadata is not being encrypted,
			//pass 4 bytes with the value 0xFFFFFFFF
			//if ($result['document']['v'] == 4 && $result['document']['EncryptMetadata'] == 'false') {
				//$hashbuilder .= 'FFFFFFFF';
				//echo "step f FFFFFFFF\n";
			//}
	
			//echo "hashbuilder final [".strlen($hashbuilder)."] $hashbuilder\n";
			//step g Finish the hash
			$result['document']['hashbuilder'] = $hashbuilder;
			$hash = md5(hex2bin($hashbuilder));
			//echo "step g hash $hash\n";

			//step h
			if ($result['document']['r'] > 2) {
				for ($i = 0; $i < 50; $i++) {
					$partial = substr($hash,0,$result['document']['key_length']/4);
					$hash = md5(hex2bin($partial));
					//echo "step h $i md5($partial) = $hash\n";
				}
			}
			//echo "step h final hash $hash\n";


			//step i
			if ($result['document']['r'] > 2)
				$key = substr($hash,0,$result['document']['key_length']/4);
			else
				$key = substr($hash,0,10);

			//echo "step i key $key\n";
			$result['document']['key'] = $key;

			logDebug("PDF Encrypted - general key is $key");
		}
	}



	//$block_no = 0;
	logDebug("all obj slicing");

	//all objects n
	unset($matches0);

	//preg_match_all("/(\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	preg_match_all("/((\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj|(\x0a|\x0d)(xref|trailer)(\x0a|\x0d))/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	//print_r($matches0);
	$ordered = array();

	if (isset($matches0[1])) {
		for($j = 0; $j< count($matches0[0]); $j++) {
			$end = '';
			if (isset($matches0[0][$j+1][1]))
				$end = $matches0[0][$j+1][1]+1;
			else
				$end = 	strlen($data);
			$dup_id = $matches0[0][$j][1]+1;
			if (isset($matches0[6][$j][0]) && ($matches0[6][$j][0] == 'xref' || $matches0[6][$j][0] == 'trailer' )) {
				$start = $matches0[0][$j][1]+1;
				$len = ($end-$start);
				$ordered[$dup_id] = array('otype' => $matches0[6][$j][0], 'obj_id' => '0', 'gen_id' => '0', 'start' => $start,
					'end' => $end, 'len' => $len, 'dup_id' => $dup_id, 'parameters' => substr($data ,$start, $len) );
				//print_r($ordered[$dup_id]);

			} else {

				$start = $matches0[4][$j][1]+strlen($matches0[4][$j][0])+4;
				$len = ($end-$start);
				$ordered[$dup_id] = array('obj_id' => $matches0[3][$j][0], 'gen_id' => $matches0[4][$j][0], 'start' => $start,
					'end' => $end, 'len' => $len, 'dup_id' => $dup_id, 'parameters' => substr($data ,$start, $len) );

			}
				
			//$ordered[$matches0[0][$j][1]] = array();
		}
	}
	//print_r($ordered);

	foreach ($ordered as $dup_id => $vals){
		$index = $vals['obj_id'].".".$vals['gen_id'].".".$dup_id;
		$result[$index] = array('object' => $vals['obj_id'], 'generation' => $vals['gen_id'],
					'obj_hex' => str_pad(dechex($vals['obj_id']), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($vals['gen_id']), 4, 0, STR_PAD_LEFT), 'dup_id' => $dup_id,
					'parameters' => $vals['parameters'], 'atype' => 'sas');
		if (isset($vals['otype']))
			$result[$index]['otype'] = $vals['otype'];
			
		$result[$index]['decrypt_part'] = lowOrder($result[$index]['obj_hex']).lowOrder($result[$index]['gen_hex']);
		if ($result['document']['v'] >= 3) {
			$result[$index]['decrypt_part'] .= "73416C54";
		}

				//handle encrypted strings
		if (isset($result['document']['key']) && $result['document']['key'] != '' && !isset($vals['otype']) ) {
					
			preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$index]['parameters'], $param1);
					//var_dump($param1);
			for($j = 0; $j< count($param1[1]); $j++) {
				//echo "test=".$param1[1][$j]."=endtest\n";
				$p = unliteral($param1[1][$j]);
				//echo "test1=".$p."=endtest1\n";
				$newParams = decryptObj($result['document'], $result[$index], $key, $p);
						
				if ($newParams != '') {
					//echo $newParams;
					$result[$index]['parameters'] = $newParams."\n[encrypted params:]".$result[$index]['parameters'];
				}
			}


		}
	}

	//print_r($result);

	//$block_no = 0;
	logDebug("no stream objects");

	//all objects n
	unset($matches0);

	preg_match_all("/(\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj(.*?)endobj/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	//logDebug("1");

	if (isset($matches0[1])) {
		$ordered = array();
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[2][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[2][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	foreach ($ordered as $dup_id => $val) {
			
		//$block_no++;
			if (!isset($result[$val[2].".".$val[3].".".$dup_id])) {
				//logDebug("2 - ".$val[2]);

				$result[$val[2].".".$val[3].".".$dup_id] = array('object' => $val[2], 'generation' => $val[3],
					'obj_hex' => str_pad(dechex($val[2]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[3]), 4, 0, STR_PAD_LEFT), 'dup_id' => $dup_id,
					'parameters' => $val[4], 'atype' => 'nos');

			
				$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[2].".".$val[3].".".$dup_id]['obj_hex']).lowOrder($result[$val[2].".".$val[3].".".$dup_id]['gen_hex']);
				if ($result['document']['v'] >= 3) {
					$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] .= "73416C54";
				}

				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[2].".".$val[3].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[2].".".$val[3].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[2].".".$val[3].".".$dup_id]['parameters'];
						}
					}


				}
			}

			
	}











	//$block_no = 0;
	logDebug("scan all streams");

	unset($matches0);
	//all streams o
	preg_match_all("/(\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\s+obj((?:(?! obj).){1,350}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)/si", $data, $matches0, PREG_OFFSET_CAPTURE);

	if (isset($matches0[0])) {
		$ordered = array();
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[2][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[2][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	foreach ($ordered as $dup_id => $val) {
		//$block_no++;
		
			$result[$val[2].".".$val[3].".".$dup_id] = array('object' => $val[2], 'generation' => $val[3],
					'obj_hex' => str_pad(dechex($val[2]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[3]), 4, 0, STR_PAD_LEFT), 'dup_id' => $dup_id,
					'parameters' => $val[4], 'atype' => 'alls');

			
			$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[2].".".$val[3].".".$dup_id]['obj_hex']).lowOrder($result[$val[2].".".$val[3].".".$dup_id]['gen_hex']);
			if ($result['document']['v'] >= 3) {
				$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] .= "73416C54";
			}





			$d = trim($val[11], "\x0A\x0D");
			$result[$val[2].".".$val[3].".".$dup_id]['md5_raw'] = md5(trim($d, "\x0A\x0D"));
			$result[$val[2].".".$val[3].".".$dup_id]['stream'] = trim($d, "\x0A\x0D");

			$t = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $d);




			$result[$val[2].".".$val[3].".".$dup_id]['md5'] = md5(trim($t, "\x0A\x0D"));
			$result[$val[2].".".$val[3].".".$dup_id]['decoded'] = trim($t, "\x0A\x0D");

			$result[$val[2].".".$val[3].".".$dup_id]['text'] = getPDFText($t);


				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[2].".".$val[3].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[2].".".$val[3].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[2].".".$val[3].".".$dup_id]['parameters'];
						}
					}


				}


	}




	//$block_no = 0;
	logDebug("scan all streams");

	unset($matches0);
	//all streams o
	preg_match_all("/(\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\s+obj((?:(?! obj).){1,350}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(\x0a|\x0d)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)/si", $data, $matches0, PREG_OFFSET_CAPTURE);

	if (isset($matches0[0])) {
		$ordered = array();
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[2][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[2][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	foreach ($ordered as $dup_id => $val) {
		//$block_no++;
		
			$result[$val[2].".".$val[3].".".$dup_id] = array('object' => $val[2], 'generation' => $val[3],
					'obj_hex' => str_pad(dechex($val[2]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[3]), 4, 0, STR_PAD_LEFT), 'dup_id' => $dup_id,
					'parameters' => $val[4], 'atype' => 'alls');

			
			$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[2].".".$val[3].".".$dup_id]['obj_hex']).lowOrder($result[$val[2].".".$val[3].".".$dup_id]['gen_hex']);
			if ($result['document']['v'] >= 3) {
				$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] .= "73416C54";
			}





			$d = trim($val[11], "\x0A\x0D");
			$result[$val[2].".".$val[3].".".$dup_id]['md5_raw'] = md5(trim($d, "\x0A\x0D"));
			$result[$val[2].".".$val[3].".".$dup_id]['stream'] = trim($d, "\x0A\x0D");

			$t = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $d);




			$result[$val[2].".".$val[3].".".$dup_id]['md5'] = md5(trim($t, "\x0A\x0D"));
			$result[$val[2].".".$val[3].".".$dup_id]['decoded'] = trim($t, "\x0A\x0D");

			$result[$val[2].".".$val[3].".".$dup_id]['text'] = getPDFText($t);


				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[2].".".$val[3].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[2].".".$val[3].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[2].".".$val[3].".".$dup_id]['parameters'];
						}
					}


				}


	}




	logDebug("js streams");
	unset($matches0);

	//js streams endobj
	//preg_match_all("/(\x0a|\x0d)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)JS[\s]{0,5}\((.*?)\)(\x0a|\x0d|>>)/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	preg_match_all("/(\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)(#4a|J)(#53|S)[\s]{0,5}\((.+?)\)endobj/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	if (isset($matches0[0])) {
		$ordered = array();
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[2][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[2][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	foreach ($ordered as $dup_id => $val) {
	
		//$block_no++;
			$result[$val[2].".".$val[3].".".$dup_id] = array('object' => $val[2], 'generation' => $val[3],
					'obj_hex' => str_pad(dechex($val[2]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[3]), 4, 0, STR_PAD_LEFT), 'dup_id' => $dup_id,
					'parameters' => $val[4], 'atype' => 'js');

			
			$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[2].".".$val[3].".".$dup_id]['obj_hex']).lowOrder($result[$val[2].".".$val[3].".".$dup_id]['gen_hex']);
			if ($result['document']['v'] >= 3) {
				$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] .= "73416C54";
			}

			$d = '';
			preg_match("/(.*)\)$/is", $val[7], $stream);
			if (isset($stream[1]))
				$d = $stream[1];
			else
				$d = $val[7];

			$d = unliteral(trim($d, "\x0A\x0D"));

		$result[$val[2].".".$val[3].".".$dup_id]['md5_raw'] = md5(trim($d, "\x0A\x0D"));
		$result[$val[2].".".$val[3].".".$dup_id]['stream'] = trim($d, "\x0A\x0D");
			$t = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $d);



		$result[$val[2].".".$val[3].".".$dup_id]['md5'] = md5(trim($t, "\x0A\x0D"));
		$result[$val[2].".".$val[3].".".$dup_id]['decoded'] = trim($t, "\x0A\x0D");
				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[2].".".$val[3].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[2].".".$val[3].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[2].".".$val[3].".".$dup_id]['parameters'];
						}
					}


				}


	}



	logDebug("js hex streams");
	unset($matches0);

	//js streams
	preg_match_all("/(\x0a|\x0d|\x20)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)(#4a|J)(#53|S)[\s]{0,5}\<(.*?)\>(\x20|\x0a|\x0d|>>|\)\/)/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	if (isset($matches0[0])) {
		$ordered = array();
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[2][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[2][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	foreach ($ordered as $dup_id => $val) {
		//$block_no++;

			$result[$val[2].".".$val[3].".".$dup_id] = array('object' => $val[2], 'generation' => $val[3],
					'obj_hex' => str_pad(dechex($val[2]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[3]), 4, 0, STR_PAD_LEFT), 'dup_id' => $dup_id,
					'parameters' => $val[4], 'atype' => 'js');

			
			$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[2].".".$val[3].".".$dup_id]['obj_hex']).lowOrder($result[$val[2].".".$val[3].".".$dup_id]['gen_hex']);
			if ($result['document']['v'] >= 3) {
				$result[$val[2].".".$val[3].".".$dup_id]['decrypt_part'] .= "73416C54";
			}





			$d = trim($val[7], "\x0A\x0D");
			$d = hex2str($d);

		$result[$val[2].".".$val[3].".".$dup_id]['md5_raw'] = md5(trim($d, "\x0A\x0D"));
		$result[$val[2].".".$val[3].".".$dup_id]['stream'] = trim($d, "\x0A\x0D");
			$t = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $d);



		$result[$val[2].".".$val[3].".".$dup_id]['md5'] = md5(trim($t, "\x0A\x0D"));
		$result[$val[2].".".$val[3].".".$dup_id]['decoded'] = trim($t, "\x0A\x0D");

				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[2].".".$val[3].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[2].".".$val[3].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[2].".".$val[3].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[2].".".$val[3].".".$dup_id]['parameters'];
						}
					}


				}

	}






	$duplicateSingle = array();

	logDebug("single filters");
	unset($matches0);
	$ordered = array();
	//single objects s
	//if ($malware['found'] < 2) {
		//echo "Looking for universal blocks with a single encoding method\n";
		//expand out Flate decoded blocks and look for javascript - large blocks
	preg_match_all("/(\d{1,4})[^\d]{1,3}(\d{1,2})\s+obj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)\/(F|#46)(i|#69)(l|#6c)(t|#74)(e|#65)(r|#72).{0,8}?\/(.{1,200}?)(.{0})(.{0})(.{0})(.{0})(.{0})(.{0})(.{0})>>(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)/si", $data, $matches0, PREG_OFFSET_CAPTURE);
		$block_no = 0;
	if (isset($matches0[0])) {
		
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[1][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[1][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	unset($matches0);
		$block_no = 0;
		preg_match_all("/(\d{1,4})[^\d]{1,3}(\d{1,2})\s+obj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)\/(F|#46)(i|#69)(l|#6c)(t|#74)(e|#65)(r|#72).{0,8}?\/(.{1,200}?)>>(.{0,100}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	if (isset($matches0[0])) {
		
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[1][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[1][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
	foreach ($ordered as $dup_id => $val) {
			//var_dump($val);
			$block_no++;
			$master_block_encoding = $block_encoding;
			
				//echo "Universal Blocks2\n";
				//echo $val[7]."\n";
			//echo "CAUGHT OBJ ID ".$val[1]."\n";
			//echo "CAUGHT GEN ID ".$val[2]."\n";

			$filter_raw = pdfhex($val[10]);

			$filters = preg_split("/( |\/)/si", trim($filter_raw), -1, PREG_SPLIT_NO_EMPTY);
			//var_dump($val);
			//echo "Filters are\n";
			//var_dump($filters);
			
			//predictors
			$predictor = '';
			if (preg_match("/\/Predictor ([\d]*)/si", $filter_raw, $matchpre))
				$predictor = $matchpre[1]; 

			$colors = '';
			if (preg_match("/\/Colors ([\d]*)/si", $filter_raw, $matchcol))
				$colors = $matchcol[1]; 

			$bitsPerComponent = '';
			if (preg_match("/\/BitsPerComponent ([\d]*)/si", $filter_raw, $matchbpc))
				$bitsPerComponent = $matchbpc[1]; 
			$columns = '';
			if (preg_match("/\/Columns ([\d]*)/si", $filter_raw, $matchcl))
				$columns = $matchcl[1]; 

			//echo "$predictor, $colors, $bitsPerComponent, $columns";


			$field = 18;
			if (!isset($val[$field]) || $val[$field] == '')
				continue;

			$d = trim($val[$field], "\x0A\x0D");


			$result[$val[1].".".$val[2].".".$dup_id] = array('object' => $val[1], 'generation' => $val[2],
					'obj_hex' => str_pad(dechex($val[1]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[2]), 4, 0, STR_PAD_LEFT),'dup_id' => $dup_id,
					'parameters' => $val[3]." ".$val[11]."/Filter /$filter_raw", 'atype' => 'single');
			if (strlen($val[10])-3 > strlen(pdfhex($val[10])) ) {
				//logDebug("Warning: Filter encoding is obfuscated ".$val[10]);
				$obfuscation = 1;
				$result[$val[1].".".$val[2].".".$dup_id]['obfuscation'] = 1;
				$result[$val[1].".".$val[2].".".$dup_id]['obfuscation_raw'] = $val[10];
				$result[$val[1].".".$val[2].".".$dup_id]['obfuscation_decode'] = pdfhex($val[10]);

			}
			
			$result[$val[1].".".$val[2].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[1].".".$val[2].".".$dup_id]['obj_hex']).lowOrder($result[$val[1].".".$val[2].".".$dup_id]['gen_hex']);
			if ($result['document']['v'] >= 3) {
				$result[$val[1].".".$val[2].".".$dup_id]['decrypt_part'] .= "73416C54";
			}

			//$d = trim($val[10], "\x0A\x0D");

			$result[$val[1].".".$val[2].".".$dup_id]['md5_raw'] = md5(trim($d, "\x0A\x0D"));
			$result[$val[1].".".$val[2].".".$dup_id]['stream'] = trim($d, "\x0A\x0D");

			$t = decryptObj($result['document'], $result[$val[1].".".$val[2].".".$dup_id], $key, $d);




			$d = $t;


			//echo "universal single $d\n";
			if ($global_test == 1) {
				echo "Found ".strlen($d)." bytes of encoded data.\n";
			}
			$result[$val[1].".".$val[2].".".$dup_id]['filter'] = '';
			foreach ($filters as $filter) {
				//echo "$filter\n";
				if ($d == '') continue;
				

				if (stripos($filter, 'ASCIIHexDecode') !== FALSE || stripos($filter, 'AHx') !== FALSE  ) {
					//echo "\n\nasciihex\n";
					$d = asciihexdecode($d);
					$master_block_encoding .= '-PA';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+ASCIIHexDecode";

				
				} else if (stripos($filter, 'LZWDecode') !== FALSE || stripos($filter, 'LZW') !== FALSE) {
					//echo "\n\nlzw\n";
					$d = lzw_decode($d);
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+LZWDecode";

					$master_block_encoding .= '-PL';

				} else if (stripos($filter, 'ASCII85Decode') !== FALSE ||stripos($filter, 'A85') !== FALSE  ) {

					//echo "\n\nascii85\n";
					$d = ascii85_decode($d);
					$master_block_encoding .= '-P8';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+ASCII85Decode";

				} else if (stripos($filter, 'CCITTFaxDecode') !== FALSE || stripos($filter, 'CCF') !== FALSE) {

					//echo "\n\nascii85\n";
					//echo "CCITT\n========\n$d\n=======\n";
					//$d = ascii85_decode($d);
					$d = ccitt_decode($d);
					$master_block_encoding .= '-CC';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+CCITTFaxDecode";

				
				} else if (stripos($filter, 'RunLengthDecode') !== FALSE || stripos($filter, 'RL') !== FALSE) {

					//echo "\n\nrun-length\n";
					$d = runlengthdecode($d);
					$master_block_encoding .= '-PR';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+RunLengthDecode";


				} else if (stripos($filter, 'FlateDecode') !== FALSE || stripos($filter, 'Fl') !== FALSE ) {
					$master_block_encoding .= '-PF';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+FlateDecode";

					//echo "\n\nflate\n";
					$t = $d;
					/*if (strlen($t) > 200000) {
						$d = substr($t,$i,strlen($t)-2);
						echo "Special ".strlen($d)." bytes.\n";
						$d = gzinflate($d, 232960);
						if ($d != '')
							break;

					} */

					for ($i = 0; $i <= 5; $i++) {
						//echo "Try $i flatedecode\n";
						$d = substr($t,$i);
						$d = flatedecode($d);
						if (strlen($d) > 4)
							break;
					}
					if ($global_test == 1 && $d == '') {
						logDebug("Warning: FlateDecode failed .s");
					}
					


				} else {
					if ($global_test == 1)
						logDebug("Unknown filter $filter");
				}


			}

			//handle predictor
			if ($predictor > 0 && $colors > 0 && $bitsPerComponent >0 && $columns>0) {
				logDebug("Predictor running ".$val[1].".".$val[2].".".$dup_id);
				$d = decodePredictor($d, $predictor, $colors, $bitsPerComponent, $columns);
				//echo $d;
			}


			//logVerbose("decoded single universal: $d");
			$result[$val[1].".".$val[2].".".$dup_id]['decoded'] = $d;
			$result[$val[1].".".$val[2].".".$dup_id]['md5'] = md5($d);

			if ($global_test == 1) {
				echo "Found ".strlen($d)." bytes of decoded data.\n";
			}


			$result[$val[1].".".$val[2].".".$dup_id]['text'] = getPDFText($d);

			//in case there's embedded objects with objects
			/*if (preg_match("/(\x0a|\x0d)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73)/si", $d)) {
				$ret = pdfSlice($d);
				unset($ret['document']);
				$result = array_merge($ret, $result);

			}*/
				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[1].".".$val[2].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[1].".".$val[2].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[1].".".$val[2].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[1].".".$val[2].".".$dup_id]['parameters'];
						}
					}


				}


		}
	//}

	$master_block_encoding = $block_encoding;


	logDebug("multi filters");
	unset($matches0);
	$ordered = array();
	//multiple objects m
	//if ($malware['found'] < 2) {
		//echo "Looking for universal blocks with multiple encoding methods\n";
		//expand out Flate decoded blocks and look for javascript - large blocks
		$flagJS = 0;
		preg_match_all("/(\d{1,4})[^\d]{1,3}(\d{1,2})\s+obj((?:(?! obj).){1,300}?)\/(F|#46)(i|#69)(l|#6c)(t|#74)(e|#65)(r|#72).{0,8}?\[(.{1,200}?)\](.{0,300}?)>>(.{0})(.{0})(.{0})(.{0})(.{0})(.{0})(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)/si", $data, $matches0, PREG_OFFSET_CAPTURE);
		//$block_no = 0;
	if (isset($matches0[0])) {
		
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[1][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[1][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}
		

		unset($matches0);

		//var_dump($matches0);
		//$block_no = 0;
	preg_match_all("/(\d{1,4})[^\d]{1,3}(\d{1,2})\s+obj((?:(?! obj).){1,300}?)\/(F|#46)(i|#69)(l|#6c)(t|#74)(e|#65)(r|#72).{0,8}?\[(.{1,200}?)\](.{1,300}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73|o|#6f)/si", $data, $matches0, PREG_OFFSET_CAPTURE);
	if (isset($matches0[0])) {
		for($j = 0; $j< count($matches0[0]); $j++) {
			$ordered[$matches0[1][$j][1]] = array();
			for($i = 1; $i< count($matches0); $i++) {
				$ordered[$matches0[1][$j][1]][$i] = $matches0[$i][$j][0];
			}
		}
	}

	foreach ($ordered as $dup_id => $val) {
			//$block_no++;
			$master_block_encoding = $block_encoding;
			//echo "Universal Blocks\n";
			//echo $val[7]." ".pdfhex($val[7])." ".trim(pdfhex($val[7]))."\n";
			$filter_raw = pdfhex($val[10]);
			$filter_raw2 = pdfhex($val[11]);
			$filters = preg_split("/( |\/)/si", trim($filter_raw), -1, PREG_SPLIT_NO_EMPTY);
			//var_dump($val);
			//echo "Filters are\n";
			//var_dump($filters);

			//predictors
			$predictor = '';
			if (preg_match("/\/Predictor ([\d]*)/si", $filter_raw2, $matchpre))
				$predictor = $matchpre[1]; 

			$colors = '';
			if (preg_match("/\/Colors ([\d]*)/si", $filter_raw2, $matchcol))
				$colors = $matchcol[1]; 

			$bitsPerComponent = '';
			if (preg_match("/\/BitsPerComponent ([\d]*)/si", $filter_raw2, $matchbpc))
				$bitsPerComponent = $matchbpc[1]; 
			$columns = '';
			if (preg_match("/\/Columns ([\d]*)/si", $filter_raw2, $matchcl))
				$columns = $matchcl[1]; 

			//echo "$predictor, $colors, $bitsPerComponent, $columns";



			$field = 18;
			if (!isset($val[$field]) || $val[$field] == '')
				continue;

			$d = trim($val[$field], "\x0A\x0D");
			//echo $d;

			

		
			$result[$val[1].".".$val[2].".".$dup_id] = array('object' => $val[1], 'generation' => $val[2],
					'obj_hex' => str_pad(dechex($val[1]), 6, 0, STR_PAD_LEFT),
					'gen_hex' => str_pad(dechex($val[2]), 4, 0, STR_PAD_LEFT),'dup_id' => $dup_id,
					'parameters' => $val[3]." "."/Filter /$filter_raw ".$val[11], 'atype' => 'multiple');
			if (strlen($val[10])-3 > strlen(pdfhex($val[10])) ) {
				//logDebug("Warning: Filter encoding is obfuscated ".$val[10]);
				$obfuscation = 1;
				$result[$val[1].".".$val[2].".".$dup_id]['obfuscation'] = 1;
				$result[$val[1].".".$val[2].".".$dup_id]['obfuscation_raw'] = $val[10];
				$result[$val[1].".".$val[2].".".$dup_id]['obfuscation_decode'] = pdfhex($val[10]);
			}
			
			
			$result[$val[1].".".$val[2].".".$dup_id]['decrypt_part'] = lowOrder($result[$val[1].".".$val[2].".".$dup_id]['obj_hex']).lowOrder($result[$val[1].".".$val[2].".".$dup_id]['gen_hex']);
			if ($result['document']['v'] >= 3) {
				$result[$val[1].".".$val[2].".".$dup_id]['decrypt_part'] .= "73416C54";
			}


			//$d = trim($val[10], "\x0A\x0D");

			$result[$val[1].".".$val[2].".".$dup_id]['md5_raw'] = md5(trim($d, "\x0A\x0D"));
			$result[$val[1].".".$val[2].".".$dup_id]['stream'] = trim($d, "\x0A\x0D");
			$t = decryptObj($result['document'], $result[$val[1].".".$val[2].".".$dup_id], $key, $d);



			$d = $t;

			$result[$val[1].".".$val[2].".".$dup_id]['filter'] = '';
			foreach ($filters as $filter) {
				//echo "[$filter]"."\n";
				
				if ($d == '') continue;

				if (stripos($filter, 'ASCIIHexDecode') !== FALSE || stripos($filter, 'AHx') !== FALSE) {
					//echo "\n\nasciihex\n";
					$d = asciihexdecode($d);
					$master_block_encoding .= '-PA';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+ASCIIHexDecode";


			
				} else if (stripos($filter, 'LZWDecode') !== FALSE || stripos($filter, 'LZW') !== FALSE) {
					//echo "\n\nlzw\n";
					$d = lzw_decode($d);

					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+LZWDecode";
					$master_block_encoding .= '-PL';

				} else if (stripos($filter, 'ASCII85Decode') !== FALSE || stripos($filter, 'A85') !== FALSE) {

					//echo "\n\nascii85\n";
					$d = ascii85_decode($d);
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+ASCII85Decode";

					$master_block_encoding .= '-P8';
				 
				} else if (stripos($filter, 'CCITTFaxDecode') !== FALSE || stripos($filter, 'CCF') !== FALSE) {

					//echo "\n\nascii85\n";
					//echo "CCITT\n========\n$d\n=======\n";
					$d = ccitt_decode($d);
					$master_block_encoding .= '-CC';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+CCITTFaxDecode";
				
				} else if (stripos($filter, 'RunLengthDecode') !== FALSE || stripos($filter, 'RL') !== FALSE) {

					//echo "\n\nrun-length\n";
					$d = runlengthdecode($d);
					$master_block_encoding .= '-PR';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+RunLengthDecode";


				} else if (stripos($filter, 'FlateDecode') !== FALSE || stripos($filter, 'Fl') !== FALSE ) {
					//echo "\n\nflateencode\n";
					$master_block_encoding .= '-PF';
					$result[$val[1].".".$val[2].".".$dup_id]['filter'] .= "+FlateDecode";

					//echo "\n\nflate\n";
					$t = $d;

					for ($i = 0; $i <= 5; $i++) {
						//echo "Try $i flatedecode\n";
						$d = substr($t,$i);
						$d = flatedecode($d);
						if ($d != '')
							break;
					}
					if ($global_test == 1 && $d == '') {
					
						logDebug( "Warning: FlateDecode failed .m");
					}



				} else {
					logDebug("Unknown filter $filter");
				}


			}

			//handle predictor
			if ($predictor > 0 && $colors > 0 && $bitsPerComponent >0 && $columns>0) {
				logDebug("Predictor running ".$val[1].".".$val[2].".".$dup_id);
				$d = decodePredictor($d, $predictor, $colors, $bitsPerComponent, $columns);
				//echo $d;
			}


			//logVerbose("decoded universal: $d");
			$result[$val[1].".".$val[2].".".$dup_id]['decoded'] = $d;
			$result[$val[1].".".$val[2].".".$dup_id]['md5'] = md5($d);

			$result[$val[1].".".$val[2].".".$dup_id]['text'] = getPDFText($d);

			//in case there's embedded objects with objects
			/*if (preg_match("/(\x0a|\x0d)(\d{1,4})[^\d]{1,3}(\d{1,2})\sobj((?:(?!\s+\d{1,2}\s+obj).){1,350}?)(s|#73)(t|#74)(r|#72)(e|#65)(a|#61)(m|#6d)(.*?)(e|#65)(n|#6e)(d|#64)(s|#73)/si", $d)) {
				$ret = pdfSlice($d);
				unset($ret['document']);
				$result = array_merge($ret, $result);

			}*/
				//handle encrypted strings
				if (isset($result['document']['key']) && $result['document']['key'] != '') {
					
					preg_match_all("/\((.*?)\)(\x0a|\x0d)/s", $result[$val[1].".".$val[2].".".$dup_id]['parameters'], $param1);
					//var_dump($param1);
					for($j = 0; $j< count($param1[1]); $j++) {
						//echo "test=".$param1[1][$j]."=endtest\n";
						$p = unliteral($param1[1][$j]);
						//echo "test1=".$p."=endtest1\n";
						$newParams = decryptObj($result['document'], $result[$val[1].".".$val[2].".".$dup_id], $key, $p);
						
						if ($newParams != '') {
							//echo $newParams;
							$result[$val[1].".".$val[2].".".$dup_id]['parameters'] = $newParams."\n[encrypted params:]".$result[$val[1].".".$val[2].".".$dup_id]['parameters'];
						}
					}


				}

		}
	//}

	$master_block_encoding = $block_encoding;



	return $result;

}


function decodePredictor($data, $predictor, $colors, $bitsPerComponent,$columns) {
	   
	if ($predictor == 10 ||  //No prediction
		$predictor == 11 ||  //Sub prediction
		$predictor == 12 ||  //Up prediction
		$predictor == 13 ||  //Average prediction
		$predictor == 14 ||  //Paeth prediction
		$predictor == 15	//Optimal prediction
			) {

		$bitsPerSample = $bitsPerComponent*$colors;
		$bytesPerSample = ceil($bitsPerSample/8);
		$bytesPerRow = ceil($bitsPerSample*$columns/8);
		$rows = ceil(strlen($data)/($bytesPerRow + 1));
		$output = '';
		$offset = 0;

		$lastRow = array_fill(0, $bytesPerRow, 0);
		for ($count = 0; $count < $rows; $count++) {
			$lastSample = array_fill(0, $bytesPerSample, 0);
			switch (ord($data[$offset++])) {
			case 0: // None of prediction
				$output .= substr($data, $offset, $bytesPerRow);
				for ($count2 = 0; $count2 < $bytesPerRow  &&  $offset < strlen($data); $count2++) {
					$lastSample[$count2 % $bytesPerSample] = $lastRow[$count2] = ord($data[$offset++]);
				}
				break;

				case 1: // Sub prediction
				for ($count2 = 0; $count2 < $bytesPerRow  &&  $offset < strlen($data); $count2++) {
					$decodedByte = (ord($data[$offset++]) + $lastSample[$count2 % $bytesPerSample]) & 0xFF;
					$lastSample[$count2 % $bytesPerSample] = $lastRow[$count2] = $decodedByte;
					$output .= chr($decodedByte);
				}
				break;

				case 2: // Up prediction
				for ($count2 = 0; $count2 < $bytesPerRow  &&  $offset < strlen($data); $count2++) {
					$decodedByte = (ord($data[$offset++]) + $lastRow[$count2]) & 0xFF;
					$lastSample[$count2 % $bytesPerSample] = $lastRow[$count2] = $decodedByte;
					$output .= chr($decodedByte);
				}
				break;

				case 3: // Average prediction
				for ($count2 = 0; $count2 < $bytesPerRow  &&  $offset < strlen($data); $count2++) {
					$decodedByte = (ord($data[$offset++]) +
								floor(( $lastSample[$count2 % $bytesPerSample] + $lastRow[$count2])/2)
							   ) & 0xFF;
					$lastSample[$count2 % $bytesPerSample] = $lastRow[$count2] = $decodedByte;
					$output .= chr($decodedByte);
				}
				break;

				case 4: // Paeth prediction
				$currentRow = array();
				for ($count2 = 0; $count2 < $bytesPerRow  &&  $offset < strlen($data); $count2++) {
					$decodedByte = (ord($data[$offset++]) +
							paeth($lastSample[$count2 % $bytesPerSample],
										 $lastRow[$count2],
										 ($count2 - $bytesPerSample  <  0)?
										  0 : $lastRow[$count2 - $bytesPerSample])
							   ) & 0xFF;
					$lastSample[$count2 % $bytesPerSample] = $currentRow[$count2] = $decodedByte;
					$output .= chr($decodedByte);
				}
				$lastRow = $currentRow;
				break;

				default:
				die('Unknown prediction tag.');
			}
		}
		return $output;
		}

	  }


function paeth($a, $b, $c) {
	// $a - left, $b - above, $c - upper left
	$p  = $a + $b - $c; // initial estimate
	$pa = abs($p - $a); // distances to a, b, c
	$pb = abs($p - $b);
	$pc = abs($p - $c);

	// return nearest of a,b,c,
	// breaking ties in order a,b,c.
	if ($pa <= $pb && $pa <= $pc) {
		return $a;
	} else if ($pb <= $pc) {
		return $b;
	} else {
		return $c;
	}
}





class LZW{ 
/**
 * Table for storing codes
 *
 * @var array
 * @access protected
 */
	var $code_value = array();
/**
 * Table for storing prefixes to codes
 *
 * @var array
 * @access protected
 */
	var $prefix_code = array();
/**
 * Table for storing individual characters
 *
 * @var array
 * @access protected
 */
	var $append_character = array();
/**
 * Output
 *
 * @var string
 * @access protected
 */
	var $out = "";
/**
 * Total size of table of values
 *
 * @var integer
 * @access protected
 */
	var $TABLE_SIZE = 5021;
/**
 * Number of bits available for encoding
 *
 * @var integer
 * @access protected
 */
	var $output_bit_count = 0;
/**
 * The actual bits for encoding
 *
 * @var string
 * @access protected
 */
	var $output_bit_buffer = "0";
/**
 * Next code in the table
 *
 * @var integer
 * @access protected
 */
	var $next_code = 258;
/**
 * Decoding: the table
 *
 * @var array
 * @access protected
 */
	var $sTable = array();
/**
 * Data to be decoded
 *
 * @var string
 * @access protected
 */
	var $data = NULL;
/**
 * Decoding: next code (same as $next_code)
 *
 * @var integer
 * @access protected
 */
	var $tIdx;
/**
 * bits in next code
 *
 * @var integer
 * @access protected
 */
	var $bitsToGet = 9;
/**
 * Position holder within data string
 *
 * @var string
 * @access protected
 */
	var $bytePointer;
/**
 * Position holder for bits in data string
 *
 * @var string
 * @access protected
 */
	var $bitPointer;
/**
 * Next value to be decoded
 *
 * @var integer
 * @access protected
 */
	var $nextData = 0;
/**
 * Next number of bits to be decoded
 *
 * @var string
 * @access protected
 */
	var $nextBits = 0;
/**
 * Table of max bit values per number of bits
 *
 * @var string
 * @access protected
 */
	var $andTable = array(511, 1023, 2047, 4095);
/**
  * Method: compress
  *      The primary method used by this class, accepts only a string as input and 
  *      returns the string compressed. 
  */
function compress($string){
  $this->output_code(256);
  $this->input = $string;

  $this->next_code=258;              /* Next code is the next available string code*/
  $string_code=ord($this->input{0});    /* Get the first code                         */

  for($i=1;$i<=strlen($this->input);$i++)
  {
	$character=ord($this->input{$i});
    $index=$this->find_match($string_code,$character);/* See if the string is in */
    if (isset($this->code_value[$index]))            /* the table.  If it is,   */
      $string_code=$this->code_value[$index];        /* get the code value.  If */
    else                                    /* the string is not in the*/
    {                                       /* table, try to add it.   */
      if ($this->next_code <= 4094)
      {
		$this->code_value[$index]=$this->next_code;
        $this->prefix_code[$index]=$string_code;
        $this->append_character[$index]=$character;
		$this->next_code++;
      }else{
	     $this->output_code(256);
		 $this->next_code = 258;
		 $this->code_value = array();
         $this->prefix_code = array();
         $this->append_character = array();
		 
		 $this->code_value[$index]=$this->next_code;
         $this->prefix_code[$index]=$string_code;
         $this->append_character[$index]=$character;
		 $this->next_code++;
	  }

      $this->output_code($string_code);  /* When a string is found  */
      $string_code=$character;            /* that is not in the table*/
    }                                   /* I output the last string*/
  }                                     /* after adding the new one*/
  
  $this->output_code(257);
  $this->output_code(0);  //Clean up
  return $this->out;
}
/**
 * Method: find_match - if PHP5 mark as private or protected
 *   Finds the matching index of the character with the table
 * @param string $hash_prefix
 * @param char $hash_character
 * @return int
 */
function find_match($hash_prefix,$hash_character){

  $index = ($hash_character << 4 ) ^ $hash_prefix;
  if ($index == 0)
    $offset = 1;
  else
    $offset = $this->TABLE_SIZE - $index;
    
	while (1){
      if (!isset($this->code_value[$index]))
        return $index;
      if ($this->prefix_code[$index] == $hash_prefix && $this->append_character[$index] == $hash_character)
        return $index;
        $index -= $offset;
      if ($index < 0)
        $index += $this->TABLE_SIZE;
    }
}
/**
 * Method: output_code - if PHP5 mark as private or protected
 *   Adds the input to the output buffer and 
 *     Adds the char code of next 8 bits of the output buffer
 * @param int $code
 */ 
function output_code($code){
	 $len = ($code < 512 ? 9 : ($code < 1024 ? 10 : ($code < 2048 ? 11 : 12)));
	 $this->output_bit_buffer = $this->bitOR($this->lshift(decbin($code),(32 - $len - $this->output_bit_count)),$this->output_bit_buffer);
     $this->output_bit_count += $len;
     while ($this->output_bit_count >= 8){
        $this->out .= chr($this->rshift($this->output_bit_buffer,24));
        $this->output_bit_buffer = $this->lshift($this->output_bit_buffer,8);
        $this->output_bit_count -= 8;
     }
}

      function decode($data) {

        if(ord($data{0}) == 0x00 && ord($data{1}) == 0x01) {
            die("LZW flavour not supported.");
        }

        $this->initsTable();

        $this->data =& $data;

        // Initialize pointers
        $this->bytePointer = 0;
        $this->bitPointer = 0;

        $this->nextData = 0;
        $this->nextBits = 0;

        $oldCode = 0;

        $string = "";
        $uncompData = "";

        while (($code = $this->getNextCode()) != 257) {
			if ($code == 256) {
                $this->initsTable();
                $code = $this->getNextCode();

                if ($code == 257) {
                    break;
                }

                $uncompData .= $this->sTable[$code];
                $oldCode = $code;

            } else {

                if ($code < $this->tIdx) {
                    $string = $this->sTable[$code];
                    $uncompData .= $string;

                    $this->addStringToTable($this->sTable[$oldCode], $string[0]);
                    $oldCode = $code;
                } else {
                    $string = $this->sTable[$oldCode];
                    $string = $string.$string[0];
                    $uncompData .= $string;

                    $this->addStringToTable($string);
                    $oldCode = $code;
                }
            }
        }
        
        return $uncompData;
    }


    /**
     * Initialize the string table. - if PHP5 mark as private or protected
     */
    function initsTable() {
        $this->sTable = array();

        for ($i = 0; $i < 256; $i++){
            $this->sTable[$i] = chr($i);
		}

        $this->tIdx = 258;
        $this->bitsToGet = 9;
    }

    /**
     * Add a new string to the string table. - if PHP5 mark as private or protected
     */
    function addStringToTable ($oldString, $newString="") {
        $string = $oldString.$newString;

        // Add this new String to the table
        $this->sTable[$this->tIdx++] = $string;

        if ($this->tIdx == 511) {
            $this->bitsToGet = 10;
        } else if ($this->tIdx == 1023) {
            $this->bitsToGet = 11;
        } else if ($this->tIdx == 2047) {
            $this->bitsToGet = 12;
        }
    }

    // Returns the next 9, 10, 11 or 12 bits - if PHP5 mark as private or protected
    function getNextCode() {
        if ($this->bytePointer == strlen($this->data)+1)
            return 257;

        $this->nextData = ($this->nextData << 8) | (ord($this->data{$this->bytePointer++}) & 0xff);
        $this->nextBits += 8;

        if ($this->nextBits < $this->bitsToGet) {
            $this->nextData = ($this->nextData << 8) | (ord($this->data{$this->bytePointer++}) & 0xff);
            $this->nextBits += 8;
        }

        $code = ($this->nextData >> ($this->nextBits - $this->bitsToGet)) & $this->andTable[$this->bitsToGet-9];
        $this->nextBits -= $this->bitsToGet;

		return $code;
    }
/**
 * The following methods allow PHP to deal with unsigned longs. 
 * They support the above primary methods. They are not warranted or guaranteed.
*/
/**
 * Method: lshift - if PHP5 mark as private or protected
 *   Used to allow class to deal with unsigned longs, bitwise left shift
 *    Two parameters, number to be shifted, and how much to shift
 * @param binary string $n
 * @param int $b
 * @return binary string
**/
  function lshift($n,$b){ return str_pad($n,($b+strlen($n)),"0");}
/**
 * Method: rshift - if PHP5 mark as private or protected
 *   Used to allow class to deal with unsigned longs, bitwise right shift
 *    Two parameters, number to be shifted, and how much to shift
 * @param binary string $n
 * @param int $b
 * @return int
 */  
  function rshift($n,$b){
   $ret = substr($n,0,(strlen($n) - $b));
   return ((int)bindec($ret));
  }
/**
 * Method: bitOR - if PHP5 mark as private or protected
 *   Used to allow class to deal with unsigned longs, bitwise OR (|)
 *    Bitwise comparison of two parameters, return string representation of not more than 32 bits
 * @param binary string $a
 * @param binary string $b
 * @return binary string
 */ 
  function bitOR($a,$b){
    $long = strlen($a) > strlen($b) ? $a : $b;
	$short = $long == $a ? $b : $a;
	$l = strrev($long);
	$s = strrev($short);
	for($r=0;$r<strlen($l);$r++){
	  $re[$r] = ($s{$r} == "1" || $l{$r} == "1") ? "1" : "0"; 
	}
	$ret = implode("",$re);
	$ret = strrev(substr($ret,0,32));
	return $ret;
  }

}






function javascriptScanEscaped(&$malware, $dec, $stringSearch, $hexSearch, $oloc = 0) {
	global $global_block_encoding;
		$is_js = 0;
		$block_encoding = $global_block_encoding;



		//check for shellcode here
		if ( strlen($dec) > 100) {


			$decAlt = $dec;
			$tiff = 0;
			if (stristr(strhex(substr($dec, 0, 4)),"49492a00")) {
				$decAlt = substr($dec, 4);
				$tiff = 1;
			}
			//logDebug( "checking for PDF string for shellcode\n");
			$shellcode = detectShellcodePlain($decAlt);

			if ($shellcode == 'SHELLCODE DETECTED') {
				logDebug( "found shell code PDF");
				$l = 0;
				if ($tiff == 0) {
					$malware["shellcode $l".uniqid('', TRUE)] = array ('searchtype' => 'shellcodePDF', 'matching' => 'full', 'keylength' =>  0, 'key' => '', 
					'search' => 'shellcode', 'location' => $l, 'top'=>0,  'keycount' => 0, 'keysum' => '',
					'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => "pdf.shellcode detected",
					'block' => strhex($decAlt),
					'block_is_decoded' => 1, 'block_encoding' => 'hex', 
					'block_size' => strlen($decAlt), 'block_type' => 'shellcode-hex',
					'block_md5' => md5($decAlt), 'block_sha1' => sha1($decAlt), 
					'block_sha256' => hash('sha256', $decAlt),
					'rawlocation' => 0, 'rawblock' => $decAlt,'rawclean' => '');
				} else {
					$malware["pdfshelltiff".uniqid('', TRUE)] = array ('searchtype' => 'pdfexploit', 'matching' => 'full', 'keylength' =>  0, 'key' => '', 
					'search' => 'pdfshelltiff', 'location' => $l, 'top'=>0,  'keycount' => 0,
					'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => "pdf.exploit base 64 shellcode in TIFF CVE-2010-0188",
					'block' => strhex($decAlt),
					'block_is_decoded' => 1, 'block_encoding' => 'hex', 
					'block_size' => strlen($decAlt), 'block_type' => 'shellcode-hex',
					'block_md5' => md5($decAlt), 'block_sha1' => sha1($decAlt), 
					'block_sha256' => hash('sha256', $decAlt),
					'rawlocation' => 0, 'rawblock' => $decAlt,'rawclean' => ''); 
				}
				$malware['found'] = 1;
				$malware['shellcode'] = 1;
				$malware['shellcodedump'] = strhex($decAlt);


			}
		}


		//search hex signatures
		//logVerbose("Scan escaped: \n====================\n$dec\n===============================");
		//$hex = strhex($dec);
		foreach($hexSearch as $pattern => $name) {
			if ($l = stripos($dec, hex2str($pattern))) {
				logDebug( "found javascript encoded $name");
				$rawstart = $l - 64;
				if ($rawstart < 0 )
					$rawstart = 0;

				$malware[$pattern.uniqid('', TRUE)] = array ('searchtype' => 'pdfexploit', 'matching' => 'full', 'keylength' =>  0, 'key' => '', 
					'search' => $pattern, 'location' => $l, 'top'=>0,  'keycount' => 0,
					'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => $name,
					'block' => strhex($dec), 'keysum' => '',
						//'block_is_decoded' => 0,  
					'block_size' => strlen($dec), 'block_type' => 'javascript-shellcode',
					'block_md5' => md5($dec), 'block_sha1' => sha1($dec), 'block_sha256' => hash('sha256', $dec),
					'block_encoding' => $global_block_encoding,
					'rawlocation' => $rawstart, 'rawblock' => substr($dec, $rawstart, 64 * 2 + strlen(hex2str($pattern))),'rawclean' => nasm($dec,$l));

				$malware['found'] = 1;
				$is_js = 1;
				$malware['shellcode'] = $l;
				$malware['shellcodedump'] = strhex($dec);

			}
		}


		//search string signatures
		foreach($stringSearch as $pattern => $name) {
			if (stristr($pattern, '?') || stristr($pattern, "\x28")) {
				preg_match("/$pattern/is", $dec, $matches, PREG_OFFSET_CAPTURE);
				//var_dump($matches);
				if (isset($matches['0']['0']) ) {
					$l = $matches['0']['1'];
					$rawstart = $l - 64;
					if ($rawstart < 0 )
						$rawstart = 0;
					logDebug("found javascript encoded string $name");
					$malware[$pattern.uniqid('', TRUE)] = array ('searchtype' => 'pdfexploit', 'matching' => 'full', 'keylength' =>  0, 'key' => '', 
						'search' => $pattern, 'location' => $l, 'top'=>0,  'keycount' => 0,
						'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => $name, 'block' => $dec, 'keysum' => '',
						//'block_is_decoded' => 0,  
						'block_size' => strlen($dec), 'block_type' => 'javascript',
						'block_md5' => md5($dec), 'block_sha1' => sha1($dec), 'block_sha256' => hash('sha256', $dec),
						 'block_encoding' => $global_block_encoding,
						'rawlocation' => $rawstart, 'rawblock' => substr($dec, $rawstart, 64 * 2 + strlen($pattern)),'rawclean' => '');
					$malware['found'] = 1;
					$is_js = 1;
				}
			} else if ($l = stripos($dec, $pattern)) {
					logDebug("found javascript encoded2 string $name");
					$rawstart = $l - 64;
					if ($rawstart < 0 )
						$rawstart = 0;
					$malware[$pattern.uniqid('', TRUE)] = array ('searchtype' => 'pdfexploit', 'matching' => 'full', 'keylength' =>  0, 
						'key' => '',  'keysum' => '',
						'search' => $pattern, 'location' => $l, 'top'=>0,  'keycount' => 0,
						'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => $name, 'block' => $dec, 
						//'block_is_decoded' => 0,  
						'block_size' => strlen($dec), 'block_type' => 'javascript',
						'block_md5' => md5($dec), 'block_sha1' => sha1($dec), 'block_sha256' => hash('sha256', $dec),
						 'block_encoding' => $global_block_encoding,
						'rawlocation' => $rawstart, 'rawblock' => substr($dec, $rawstart, 64 * 2 + strlen($pattern)),'rawclean' => '');
					$malware['found'] = 1;
					$is_js = 1;
			}
		}





		//search quoted strings ""
		preg_match_all("/\"(.{1,9600}?)\"/is", $dec, $matches2, PREG_SET_ORDER);
		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;
			//echo "need to decode ".$encoded[1]."\n";

			$strings = reghex2str($encoded[1]);
			$global_block_encoding .= '-RH';
			$strings = jsascii2str($strings);
			$global_block_encoding .= '-JA';
			$strings = unicode_to_shellcode($strings);
			$global_block_encoding .= '-UC';

			if ($strings == 0x0000) {
				//logVerbose("invalid escaped string\n".$encoded[1]."\n");
				if (is_base64($encoded[1]) && strlen($encoded[1]) > 100 ) {
					//logVerbose("string is base 64 encoded, testing for shellcode\n");
					$global_block_encoding = $block_encoding . "-64";
					$strings = base64_decode($encoded[1]);
					if ($strings != "")
						javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
				}
			} else {

				javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
			}

		}
		//search quoted strings ''
		preg_match_all("/'(.{1,9600}?)'/is", $dec, $matches2, PREG_SET_ORDER);
		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;
			//echo "need to decode ".$encoded[1]."\n";

			$strings = reghex2str($encoded[1]);
			$global_block_encoding .= '-RH';
			$strings = jsascii2str($strings);
			$global_block_encoding .= '-JA';
			$strings = unicode_to_shellcode($strings);
			$global_block_encoding .= '-UC';

			if ($strings == 0x0000) {
				//logVerbose("invalid escaped string\n".$encoded[1]."\n");
				if (is_base64($encoded[1]) && strlen($encoded[1]) > 100 ) {
					//logVerbose("string is base 64 encoded, testing for shellcode\n");
					$global_block_encoding = $block_encoding . "-64";
					$strings = base64_decode($encoded[1]);
					if ($strings != "")
						javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
				}

			} else {
				javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
			}

			//echo $strings;


		}




		//try char from code decoding
		preg_match_all("/fromCharCode.{0,2}?\((.*?)\)/is", $dec, $matches2, PREG_SET_ORDER);
		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;

			//echo "need to decode ".$encoded[1]."\n";
			$strings = code2str($encoded[1]);
			$global_block_encoding .= '-CF';
			//echo "fixed\n$strings\n";
			javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
		}

		$global_block_encoding = $block_encoding;


	return $malware;
}

function is_base64($data) {
	if (preg_match( '/^[A-Za-z=\/\+]+$/s', trim($data)) );
		return 1;
	return 0;
	}



function javascriptScan(&$malware, $dec, $stringSearch, $hexSearch) {
		global $global_block_encoding;
		$block_encoding = $global_block_encoding;

		//logVerbose("Scan javascript: \n$dec");


		$stringsFixed = reghex2str($dec);
		//logVerbose("DECODED HEX STR");
		//logVerbose($stringsFixed);

		if ($dec != $stringsFixed)
			$global_block_encoding .= '-RH';

		foreach($stringSearch as $pattern => $name) {
			//if ($l = stripos($stringsFixed, $pattern)) {
			if (stristr($pattern, '?') || strstr($pattern, "\x28")) {
				preg_match("/$pattern/is", $stringsFixed, $matches, PREG_OFFSET_CAPTURE);
				//var_dump($matches);
				if (isset($matches['0']['0']) ) {
					$l = $matches['0']['1'];
					$rawstart = $l - 64;
					if ($rawstart < 0 )
						$rawstart = 0;
					logDebug("found javascript string $name");
					$malware[$pattern.uniqid('', TRUE)] = array ('searchtype' => 'pdfexploit', 'matching' => 'full', 'keylength' =>  0, 'key' => '', 
						'search' => $pattern, 'location' => $l, 'top'=>0,  'keycount' => 0, 'keysum' => '',
						'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => $name,
						'block' => $stringsFixed, 'block_is_decoded' => 1, 'block_encoding' => 'reghex',
						'block_size' => strlen($stringsFixed), 'block_type' => 'javascript',
						'block_md5' => md5($stringsFixed), 'block_sha1' => sha1($stringsFixed),
						'block_sha256' => hash('sha256', $stringsFixed),
						'block_encoding' => $global_block_encoding,
						'rawlocation' => $rawstart, 'rawblock' => substr($stringsFixed, $rawstart, 64 * 2 + strlen($pattern)),'rawclean' => '');
					$malware['found'] = 1;
				}
			} else if ($l = stripos($stringsFixed, $pattern)) {
					logDebug("found javascript string $name");
					$rawstart = $l - 64;
					if ($rawstart < 0 )
						$rawstart = 0;
					$malware[$pattern.uniqid('', TRUE)] = array ('searchtype' => 'pdfexploit', 'matching' => 'full', 'keylength' =>  0, 
						'key' => '',  'keysum' => '',
						'search' => $pattern, 'location' => $l, 'top'=>0,  'keycount' => 0,
						'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => $name,
						'block' => $stringsFixed, 'block_is_decoded' => 1, 'block_encoding' => 'reghex', 
						'block_size' => strlen($stringsFixed), 'block_type' => 'javascript',
						'block_md5' => md5($stringsFixed), 'block_sha1' => sha1($stringsFixed), 
						'block_sha256' => hash('sha256', $stringsFixed),
						'block_encoding' => $global_block_encoding,
						'rawlocation' => $rawstart, 'rawblock' => substr($stringsFixed, $rawstart, 64 * 2 + strlen($pattern)),'rawclean' => '');
					$malware['found'] = 1;

			}
		}

		preg_match_all("/\"(.{1,32000}?)\"/is", $stringsFixed, $matches2, PREG_SET_ORDER);
		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;
			if ($dec != $stringsFixed)
				$global_block_encoding .= '-RH';
			$global_block_encoding .= '-ES';
			//echo "need to decode ".$encoded[1]."\n";
			//$strings = reghex2str($encoded[1]);
			$strings = jsascii2str($encoded[1]);
			//logVerbose("1: ===$strings===\n");
			$global_block_encoding .= '-JA';
			$strings = unicode_to_shellcode($strings);
			//logVerbose("2: ===$strings===\n");
			$global_block_encoding .= '-UC';
			if ($strings == 0x0000) {
				//logVerbose("invalid escaped string\n".$encoded[1]."\n");
				
				if (is_base64($encoded[1]) && strlen($encoded[1]) > 100 ) {
					//logVerbose("string is base 64 encoded, testing for shellcode\n");

					$global_block_encoding = $block_encoding . "-64";
					$strings = base64_decode($encoded[1]);
					if ($strings != "")
						javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
				}
			} else {
				//echo "fixed\n".$encoded[1]."\n===".strhex($strings)."===\n";
				javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);

			}


		}

		preg_match_all("/'(.{1,32000}?)'/is", $stringsFixed, $matches2, PREG_SET_ORDER);

		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;
			if ($dec != $stringsFixed)
				$global_block_encoding .= '-RH';
			$global_block_encoding .= '-ES';
			//echo "need to decode ".$encoded[1]."\n";
			//$strings = reghex2str($encoded[1]);
			$strings = jsascii2str($encoded[1]);
			$global_block_encoding .= '-JA';
			$strings = unicode_to_shellcode($strings);
			$global_block_encoding .= '-UC';
			if ($strings == 0x0000) {
				//logVerbose("invalid escaped string\n".$encoded[1]."\n");
				if (is_base64($encoded[1]) && strlen($encoded[1]) > 100 ) {
					//logVerbose("string is base 64 encoded, testing for shellcode\n");
					$global_block_encoding = $block_encoding . "-64";
					$strings = base64_decode($encoded[1]);
					if ($strings != "")
						javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
				}
			} else {
				//echo "$strings\n";
				javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
			}

		}

		//CVE-2010-0188
		preg_match_all("/\>(.*?)\</is", $stringsFixed, $matches2, PREG_SET_ORDER);
		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;
			//if ($dec != $stringsFixed)
			//	$global_block_encoding .= '-RH';
			//$global_block_encoding .= '-ES';
			//echo "need to decode ".$encoded[1]."\n";
			//$strings = reghex2str($encoded[1]);
			//$strings = jsascii2str($encoded[1]);
			//$global_block_encoding .= '-JA';
			//$strings = unicode_to_shellcode($strings);
			//$global_block_encoding .= '-UC';
			//if ($strings == 0x0000) {
				//logVerbose("trying to process XFA block\n".$encoded[1]."\n");
				if (is_base64($encoded[1]) && strlen($encoded[1]) > 100 ) {
					//logVerbose("string is base 64 encoded, testing for shellcode\n");
					$global_block_encoding = $block_encoding . "-64";
					$strings = base64_decode($encoded[1]);
					if ($strings != "")
						javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
				}
			//} else {
			//	//echo "$strings\n";
			//	javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
			//}

		}


		preg_match_all("/fromCharCode.{0,2}?\((.*?)\)/is", $stringsFixed, $matches2, PREG_SET_ORDER);
		foreach ($matches2 as $encoded) {
			$global_block_encoding = $block_encoding;
			if ($dec != $stringsFixed)
				$global_block_encoding .= '-RH';
			//echo "need to decode ".$encoded[1]."\n";
			$strings = code2str($encoded[1]);
			$global_block_encoding .= '-CF';

			//echo "fixed\n$strings\n";
			javascriptScanEscaped($malware, $strings, $stringSearch, $hexSearch);
		}


		$global_block_encoding = $block_encoding;
	return $malware;
}




function findHiddenJS($string) {
	if (ctype_print($string) ) {
		$newstring = '';
		$tmp = '';
		$data = '';

		for($i = 0; $i < strlen($string) ; $i++) {
			if (ctype_xdigit($string[$i])) {
				$tmp .= $string[$i];
			} else {
				
				if (strlen($tmp) == 4) {
					$data .= chr(hexdec ($tmp[2].$tmp[3])).chr(hexdec($tmp[0].$tmp[1]));
					$tmp = '';
				} else {
					$ascii = base_convert ($tmp,16,10);
      					$data .= chr ($ascii);
					$tmp = '';
				}
			}
		}
		return $data;
	}
	return $string;
}



function cleanHex($string) {
	$tmp = '';
	for($i = 0; $i < strlen($string) ; $i++) {
		if (ctype_xdigit($string[$i])) {
			$tmp .= $string[$i];
		} 
	}
	return $tmp;
}




function reghex2str($hex)
{
	$str = '';
	for ($i = 0; $i < strlen($hex); $i++) {
		if ($i+3 <= strlen($hex) && $hex[$i] == '\\' && $hex[$i+1] == 'x' && ctype_alnum($hex[$i+2]) &&  ctype_alnum($hex[$i+3])) {
			$n = $hex[$i+2].$hex[$i+3];
			$str .= chr(hexdec($n));
			$i+=3;
 		} else {
			$str .= $hex[$i];
		}

	}
	

  return $str;
}

function code2str($hex)
{
	//echo "before $hex\n";
	$str = '';
	for ($i = 0; $i < strlen($hex); $i++) {
		if ($i+2 <= strlen($hex) && ctype_alnum($hex[$i]) && ctype_alnum($hex[$i+1]) && ctype_alnum($hex[$i+2]) && ctype_alnum($hex[$i+3])) {
			//$n = $hex[$i].$hex[$i+1].$hex[$i+2];
			$str .= chr($hex[$i+2].$hex[$i+3]).chr($hex[$i].$hex[$i+1]);
			$i+=3;
		} else if ($i+2 <= strlen($hex) && ctype_alnum($hex[$i]) && ctype_alnum($hex[$i+1]) && ctype_alnum($hex[$i+2])) {
			$n = $hex[$i].$hex[$i+1].$hex[$i+2];
			$str .= chr($n);
			$i+=2;
 		} else if ($i+2 <= strlen($hex) && ctype_alnum($hex[$i]) && ctype_alnum($hex[$i+1])) {
			$n = $hex[$i].$hex[$i+1];
			$str .= chr($n);
			$i+=1;
 		} else if ($i+1 <= strlen($hex) && ctype_alnum($hex[$i]) ) {
			$n = $hex[$i];
			$str .= chr($n);
			//$i+=1;
		} else {
			//$str .= $hex[$i];
		}

	}
	//echo "after $str\n";

  return $str;
}


function jsascii2str($hex)
{
	//echo "before $hex\n";
	$str = '';
	for ($i = 0; $i < strlen($hex); $i++) {
		if ($i+3 <= strlen($hex) && $hex[$i] == '\\' && ctype_alnum($hex[$i+1]) && ctype_alnum($hex[$i+2]) &&  ctype_alnum($hex[$i+3])) {
			$n = $hex[$i+1].$hex[$i+2].$hex[$i+3];
			$str .= chr($n);
			$i+=3;
 		} else if ($i+3 <= strlen($hex) && $hex[$i] == '\\' && ctype_alnum($hex[$i+1]) && ctype_alnum($hex[$i+2]) ) {
			$n = $hex[$i+1].$hex[$i+2];
			$str .= chr($n);
			$i+=2;
 		} else if ($i+2 <= strlen($hex) && $hex[$i] == '\\' && ctype_alnum($hex[$i+1]) ) {
			$n = $hex[$i+1];
			$str .= chr($n);
			$i+=1;
		} else {
			$str .= $hex[$i];
		}

	}
	//echo "after $str\n";

  return $str;
}



function unicode_to_shellcode($url)
{
  //split the URL into an array
	//echo $url."\n";
  $url=str_replace('\u', '%u', $url);
 	//echo $url."\n";
  $url_array = explode ("%", $url);
  //Make sure we have an array
  if (is_array($url_array))
  {
    //Loop while the key/value pair of the array
    //match our list items
	$ret = '';
    while (list ($k,$v) = each ($url_array))
    {
	if (stristr($v, 'u') || stristr($v, 'z')) {
		$unicode = trim($v, 'uUzZ');
		//$ascii = utf8_decode($unicode);
		if (isset ($unicode[3])) {
     			$ascii = chr(hexdec ($unicode[2].$unicode[3])).chr(hexdec($unicode[0].$unicode[1]));
			//echo "try to convert $unicode to ".$ascii." ".$unicode[0].$unicode[1]." ".$unicode[2].$unicode[3]."\n";
			$ret .= $ascii;
		}
	} else if (strlen($v) == 2) {

	       //use base_convert to convert each character
      		$ascii = base_convert ($v,16,10);
      		$ret .= chr ($ascii);
		//$ret .= $v;
	} else {

	       //use base_convert to convert each character
      		//$ascii = base_convert ($v,16,10);
      		//$ret .= chr ($ascii);
		$ret .= $v;
	}
    }
 }
 //return the decoded URL
 return ("$ret");
}


function hex2str($hex)
{
	$str = '';
  for($i=0;$i<strlen($hex);$i+=2)
  {
    $str.=chr(hexdec(substr($hex,$i,2)));
  }
  return $str;
}

function decode_replace($string)
{
	return preg_replace("/([A-Z])/" ,'%', $string);
}

function checkBlockHash($md5) {
	global $PDFblockHash;
	$malware = array('found' => 0);

	$malware['found'] = 0;
	//$md5 = md5(trim($data, "\x0A\x0D"));
	//echo "block hash is $md5 ".strlen(trim($data, "\x0A\x0D"))."\n";
	//echo "TEST ".substr(trim($data, "\x0A\x0D"), 0, 16)."\n";
	//echo "bottom ".strhex(substr(trim($data, "\x0A\x0D"), -16))."\n";

	if (isset($PDFblockHash[$md5]) ) {

		logDebug("Found ".$PDFblockHash[$md5]);

		$malware[$md5.uniqid('', TRUE)] = array ('searchtype' => 'block', 'matching' => 'full', 'keylength' => 0, 'key' => 0, 
					'search' => $md5, 'location' => 0, 'top'=>0,  'keycount' => 0,
					'keylocation' => 0, 'keyaccuracy' => 0, 'searcherrors' => 0, 'virustype' => $PDFblockHash[$md5],
					'rawlocation' => 0, 'rawblock' => '', 'block' => '', 'block_type' => '',
					'rawclean' => '',
					'keysum' => '');
		$malware['found'] = 1;
	}
	return $malware;
}



function detectShellcodePlain($data) {
	global $global_libemu, $malwaredir;
	//$malware['found'] = 0;

	$filename = $malwaredir."shell_".uniqid();
	$fp = fopen($filename, "w");
	fwrite($fp, $data);
	fclose($fp);
	$le = explode(';', $global_libemu);
	$shellcode_scan = '';
	if (isset($le[2]) && is_executable($le[2])) {
		$shellcode_scan = exec("$global_libemu ".escapeshellarg($filename));
	} 
	unlink($filename);

	if (strstr($shellcode_scan, 'SHELLCODE DETECTED')) {
		return "SHELLCODE DETECTED";
	}
	


	return "not found";
}


function nasm($data, $loc = 0) {
	global $malwaredir, $global_nasm;

	$filename = $malwaredir."shell_".uniqid();
	$fp = fopen($filename, "w");
	fwrite($fp, $data);
	fclose($fp);
	//echo "exec "."$global_nasm -o ".escapeshellarg($loc)." -u $filename\n";
	if (is_executable($global_nasm)) {
		exec("$global_nasm -o ".escapeshellarg($loc)." -u $filename", $output0);
		$output = implode("\n", $output0);
	} else
		$output = '';
	//echo $output;
	return $output;
}



function dec_to_hex($dec)
{
    $sign = ""; // suppress errors
    if( $dec < 0){ $sign = "-"; $dec = abs($dec); }

    $hex = Array( 0 => 0, 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 5,
                  6 => 6, 7 => 7, 8 => 8, 9 => 9, 10 => 'a',
                  11 => 'b', 12 => 'c', 13 => 'd', 14 => 'e',   
                  15 => 'f' );
       
    do
    {
        $h = $hex[($dec%16)] . $h;
        $dec /= 16;
    }
    while( $dec >= 1 );
   
    return $sign . $h;
} 

function ccitt_decode($rawdata, $params = array()) {


$ccitt_eol="000000000001";
$ccitt_eof="000000000001000000000001000000000001000000000001000000000001000000000001";

$ccitt_white_term = array('00110101' => '0','000111' => '1','0111' => '2','1000' => '3','1011' => '4','1100' => '5','1110' => '6','1111' => '7','10011' => '8','10100' => '9','00111' => '10','01000' => '11','001000' => '12','000011' => '13','110100' => '14','110101' => '15','101010' => '16','101011' => '17','0100111' => '18','0001100' => '19','0001000' => '20','0010111' => '21','0000011' => '22','0000100' => '23','0101000' => '24','0101011' => '25','0010011' => '26','0100100' => '27','0011000' => '28','00000010' => '29','00000011' => '30','00011010' => '31','00011011' => '32','00010010' => '33','00010011' => '34','00010100' => '35','00010101' => '36','00010110' => '37','00010111' => '38','00101000' => '39','00101001' => '40','00101010' => '41','00101011' => '42','00101100' => '43','00101101' => '44','00000100' => '45','00000101' => '46','00001010' => '47','00001011' => '48','01010010' => '49',
'01010011' => '50','01010100' => '51','01010101' => '52','00100100' => '53','00100101' => '54','01011000' => '55','01011001' => '56','01011010' => '57','01011011' => '58','01001010' => '59','01001011' => '60','00110010' => '61','00110011' => '62','00110100' => '63');

$ccitt_white_make = array('11011' => '64','10010' => '128','010111' => '192','0110111' => '256','00110110' => '320','00110111' => '384','01100100' => '448','01100101' => '512','01101000' => '576','01100111' => '640','011001100' => '704','011001101' => '768','011010010' => '832','011010011' => '896','011010100' => '960','011010101' => '1024','011010110' => '1088','011010111' => '1152','011011000' => '1216','011011001' => '1280','011011010' => '1344','011011011' => '1408','010011000' => '1472','010011001' => '1536','010011010' => '1600','011000' => '1664','010011011' => '1728',
'00000001000' => '1792','00000001100' => '1856','00000001101' => '1920','000000010010' => '1984','000000010011' => '2048','000000010100' => '2112','000000010101' => '2176','000000010110' => '2240','000000010111' => '2304','000000011100' => '2368','000000011101' => '2432','000000011110' => '2496','000000011111' => '2560');


$ccitt_black_term = array('0000110111' => '0','010' => '1','11' => '2','10' => '3','011' => '4','0011' => '5','0010' => '6','00011' => '7','000101' => '8','000100' => '9','0000100' => '10','0000101' => '11','0000111' => '12','00000100' => '13','00000111' => '14','000011000' => '15','0000010111' => '16','0000011000' => '17','0000001000' => '18','00001100111' => '19','00001101000' => '20','00001101100' => '21','00000110111' => '22','00000101000' => '23','00000010111' => '24','00000011000' => '25','000011001010' => '26','000011001011' => '27','000011001100' => '28','000011001101' => '29','000001101000' => '30','000001101001' => '31','000001101010' => '32','000001101011' => '33','000011010010' => '34','000011010011' => '35','000011010100' => '36','000011010101' => '37','000011010110' => '38','000011010111' => '39','000001101100' => '40','000001101101' => '41','000011011010' => '42','000011011011' => '43','000001010100' => '44','000001010101' => '45','000001010110' => '46','000001010111' => '47','000001100100' => '48','000001100101' => '49',
'000001010010' => '50','000001010011' => '51','000000100100' => '52','000000110111' => '53','000000111000' => '54','000000100111' => '55','000000101000' => '56','000001011000' => '57','000001011001' => '58','000000101011' => '59','000000101100' => '60','000001011010' => '61','000001100110' => '62','000001100111' => '63');



$ccitt_black_make = array('0000001111' => '64','000011001000' => '128','000011001001' => '192','000001011011' => '256','000000110011' => '320','000000110100' => '384','000000110101' => '448','0000001101100' => '512','0000001101101' => '576','0000001001010' => '640','0000001001011' => '704','0000001001100' => '768','0000001001101' => '832','0000001110010' => '896','0000001110011' => '960','0000001110100' => '1024','0000001110101' => '1088','0000001110110' => '1152','0000001110111' => '1216','0000001010010' => '1280','0000001010011' => '1344','0000001010100' => '1408','0000001010101' => '1472','0000001011010' => '1536','0000001011011' => '1600','0000001100100' => '1664','0000001100101' => '1728',
'00000001000' => '1792','00000001100' => '1856','00000001101' => '1920','000000010010' => '1984','000000010011' => '2048','000000010100' => '2112','000000010101' => '2176','000000010110' => '2240','000000010111' => '2304','000000011100' => '2368','000000011101' => '2432','000000011110' => '2496','000000011111' => '2560');



//convert all the data to binary

	$bindata = '';
	for ($i = 0; $i < strlen($rawdata); $i++) {
		$bindata .= str_pad(  decbin(ord($rawdata[$i])), 8,'0', STR_PAD_LEFT);
	}

	//echo "binary $bindata\n";

	//then grab clear signal to confirm format
	if (substr($bindata, 0, 12) == $ccitt_eol) {
		//echo "received eol, proceeding\n";
	} else {
		//echo "format not as expected, exiting\n";
		return '';
	}


	$binout = '';
	$white = 1;
	$i = 12;
	while ( $i < strlen($bindata) ) {
		$f = 0;
		$curr = array('13' => substr($bindata, $i, 13) );
		$curr['12'] = substr($curr['13'], 0, 12);
		$curr['11'] = substr($curr['13'], 0, 11);
		$curr['10'] = substr($curr['13'], 0, 10);
		$curr['9'] = substr($curr['13'], 0, 9);
		$curr['8'] = substr($curr['13'], 0, 8);
		$curr['7'] = substr($curr['13'], 0, 7);
		$curr['6'] = substr($curr['13'], 0, 6);
		$curr['5'] = substr($curr['13'], 0, 5);
		$curr['4'] = substr($curr['13'], 0, 4);
		$curr['3'] = substr($curr['13'], 0, 3);
		$curr['2'] = substr($curr['13'], 0, 2);

		if ($curr['12'] == $ccitt_eol) {
			$white = 1;
			$i += 12;
			$f++;
			//echo "eol\n";
		} else if ($white == 1) {
			for ($j = 13; $j > 1; $j--) {
				$a = $curr[$j];
				if (isset($ccitt_white_term[$a])) {
					$binout .= str_pad('', $ccitt_white_term[$a],'1', STR_PAD_LEFT);
					$white = 0;
					$i += strlen($curr[$j]);
					//echo "whiteterm ".$ccitt_white_term[$a]." jump to $i\n";
					$f++;
					break;
				} else if (isset($ccitt_white_make[$a])) {
					$binout .= str_pad('', $ccitt_white_make[$a],'1', STR_PAD_LEFT);
					
					$i += strlen($curr[$j]);
					//echo "white ".$ccitt_white_make[$a]." jump to $i\n";
					$f++;
					break;
				}
			
			}
		} else { //do black
			for ($j = 13; $j > 1; $j--) {
				$a = $curr[$j];
				if (isset($ccitt_black_term[$a])) {
					$binout .= str_pad('', $ccitt_black_term[$a],'0', STR_PAD_LEFT);
					$white = 1;
					$i += strlen($curr[$j]);
					//echo "blackterm ".$ccitt_black_term[$a]." jump to $i\n";
					$f++;

					break;
				} else if (isset($ccitt_black_make[$a])) {
					$binout .= str_pad('', $ccitt_black_make[$a],'0', STR_PAD_LEFT);
					$i += strlen($curr[$j]);
					//echo "black ".$ccitt_black_make[$a]." jump to $i\n";
					$f++;
					
					break;
				}
			
			}
		}
		if ($f == 0)
			break;

	}
	//echo "out $binout\n";

	$out = '';
	for ($i = 0; $i < strlen($binout); $i+=8) {
		$out .= chr( bindec(substr($binout, $i, 8)) );
	}

	//echo "done $out\n";
	return $out;

}


function getPDFText($data) {
	$result = '';
	if (preg_match_all ('/\(([^\)]+)\)/', $data, $matches))
		$result .= join ('', $matches[1]); 
	return unliteral($result); //return what was found
}


//optional variable to save files in the directory below in a md5 subdir
$global_store_files = 0;

//directory to store extracted PDF objects
$pdfdir = './';

//export all object data to command line
$global_export_all = 0;


$global_engine="70"; //detection engine update

	$PDFstringSearch = array('une(.{0,6}?)sca(.{0,6}?)pe([^\)]{0,6}?)\(' => 'suspicious.obfuscation using unescape',
//openaction (#4f|O)(#70|p)(#65|e)(#6e|n)(#41|A)(#63|c)(#74|t)(#69|i)(#6f|o)(#6e|n)
'un(.{0,6}?)esc(.{0,6}?)ape([^\)]{0,6}?)\(' => 'suspicious.obfuscation using unescape', 
'unesc([\W]{0,6}?)ape' => 'suspicious.obfuscation using unescape', 
'c([\W]{0,4}?)h([\W]{0,4}?)a([\W]{0,4}?)r([\W]{0,4}?)C([\W]{0,3}?)o([\W]{0,3}?)d([\W]{0,3}?)e([\W]{0,3}?)A(.{0,3}?)t' => 'suspicious.obfuscation using charCodeAt', 
'u([\W]{0,6}?)n([\W]{0,6}?)e([\W]{0,6}?)s([\W]{0,6}?)c([\W]{0,6}?)a([\W]{0,6}?)p([\W]{0,6}?)e' => 'suspicious.obfuscation using unescape',
'unescape([^\)]{0,6}?)\(' => 'suspicious.obfuscation using unescape',
'nopblock' => 'suspicious.string nopblock', 
//'u9090' => 'suspicious.string unicode nop', 
//'u0c0c' => 'suspicious.string heap spray shellcode', 
//'0c0c0c0c' => 'suspicious.string heap spray shellcode', 
'eval(\s{0,3}?)\(' => 'suspicious.obfuscation using eval',
//'eval\(' => 'suspicious.obfuscation using eval',
'eval\\' => 'suspicious.obfuscation using eval',
//'eval (' => 'suspicious.obfuscation using eval',
'application/x-javascript' => 'suspicious.javascript in XFA block',
'application#2Fx-javascript' => 'suspicious.javascript in XFA block',
'application#2Fpdf' => 'suspicious.pdf embedded PDF file',
//'application/pdf' => 'suspicious.pdf embedded PDF file',
'eval,' => 'suspicious.obfuscation using eval',
'toString\(' => 'suspicious.obfuscation toString',
'substr\(' => 'suspicious.obfuscation using substr',
"'e'(.{1,30}?)'va'(.{1,3}?)'l" => 'suspicious.obfuscation using eval',
"'re'(.{1,24}?)'place'"  => 'suspicious.obfuscation using String.replace',
'"l","v","e","a"' => 'suspicious.obfuscation using eval',
'"u","s","p","c","n","e","a",'  => 'suspicious.obfuscation using unescape',
'"rCo","t","cha","","deA"' => 'suspicious.obfuscation using String.fromCharCode',
'"e","l","a","v"' => 'suspicious.obfuscation using eval',
'"s","n","a","e","c","u","e","p"'  => 'suspicious.obfuscation using unescape',
'"deA","cha","rCo","t"' => 'suspicious.obfuscation using String.fromCharCode',
'=(\s{0,6}?)eval' => 'suspicious.obfuscation using eval',
'f(.{0,6}?)r(.{0,6}?)o([\W]{0,6}?)m([\W]{0,6}?)C([\W]{0,6}?)h([\W]{0,6}?)a(.{0,6}?)r(.{0,6}?)C(.{0,6}?)o([\W]{0,6}?)d([\W]{0,6}?)e' => 'suspicious.obfuscation using String.fromCharCode',
'.fromCharC' => 'suspicious.obfuscation using String.fromCharCode',
'.replace' => 'suspicious.obfuscation using String.replace',
'\.substring(\s{0,3}?)\(' => 'suspicious.obfuscation using substring',
'byteToChar' => 'suspicious.obfuscation using util.byteToChar',
 '%u9090' => 'suspicious.string Shellcode NOP sled',
'"%" + "u" + "0" + "c" + "0" + "c" + "%u" + "0" + "c" + "0" + "c"' => 'suspicious.string heap spray shellcode', 
'%u4141%u4141' => 'suspicious.string shellcode',
'Run_Sploit'=>'suspicious.string Run_Sploit',
'HeapSpray'=>'suspicious.string HeapSpray',
'writeMultiByte' => 'suspicious.flash writeMultiByte',
'addFrameScript' => 'suspicious.flash addFrameScript',
//fuzzString('JBIG2Decode') => 'pdf.exploit vulnerable JBIG2Decode CVE-2009-0658',
'\/'.fuzzString('RichMedia') => 'suspicious.flash Adobe Shockwave Flash in a PDF define obj type',
'/R#69chM#65#64ia#53e#74ti#6e#67#73/' => 'suspicious.flash obfuscated name',
//'Subtype/3D' => 'pdf.exploit suspicious use of 3D CVE-2009-3954',
//'model/u3d' => 'pdf.exploit suspicious use of U3D CVE-2009-3953 CVE-2009-3959',
'Predictor 02(\s{0,2}?)\/(\s{0,2}?)Colors 1073741838' => 'pdf.exploit FlateDecode Stream Predictor 02 Integer Overflow CVE-2009-3459',
'\/Colors \d{5,15}?' => 'pdf.exploit colors number is high CVE-2009-3459',
'URI.{1,30}?\/\.\.\/\.\.' => 'pdf.exploit URI directory traversal',
'URI.{1,65}?system32' => 'pdf.exploit URI directory traversal system32',
'\/Action(.{0,64}?)\.exe' => 'pdf.exploit execute EXE file',
'\/Action(.{0,64}?)system32' => 'pdf.exploit access system32 directory',
//'exportDataObject' => 'pdf.exploit accessing embedded files exportDataObject',
'Launch/Type/Action/Win' => 'pdf.exploit execute action command',
'p([\W]{0,2}?)r([\W]{0,2}?)i([\W]{0,2}?)n([\W]{0,2}?)t([\W]{0,1}?)S([\W]{0,2}?)e([\W]{0,2}?)p([\W]{0,2}?)s' => 'pdf.exploit printSeps memory heap corruption CVE-2010-4091',

':++$,$$$$:' => 'suspicious.obfuscation jjencoded javascript',
'$$:++$,$$$' => 'suspicious.obfuscation jjencoded javascript',

'g(\W{0,2}?)e(\W{0,2}?)t(\W{0,2}?)A(.{0,2}?)n(.{0,1}?)n(.{0,2}?)o(.{0,2}?)t' => 'suspicious.obfuscation getAnnots access blocks',
'(\.|=)s(.{0,6}?)y(.{0,6}?)n(.{0,6}?)c(.{0,6}?)A(.{0,6}?)n(.{0,6}?)n(.{0,6}?)o(.{0,6}?)t(.{0,6}?)S(.{0,6}?)c(.{0,6}?)a(.{0,6}?)n' => 'suspicious.obfuscation syncAnnotScan to access blocks',
'i(.{0,4}?)n(.{0,4}?)f(.{0,4}?)o(.{0,4}?)\.(.{0,4}?)T(.{0,4}?)r(.{0,4}?)a(.{0,4}?)i(.{0,4}?)l(.{0,4}?)e(.{0,4}?)r' => 'suspicious.obfuscation info.Trailer to access blocks',
'a(.{0,6}?)p(.{0,6}?)p\.(.{0,6}?)s(.{0,6}?)e(.{0,6}?)t(.{0,6}?)T(.{0,6}?)i(.{0,6}?)m(.{0,6}?)e(.{0,6}?)O(.{0,6}?)u(.{0,6}?)t' => 'suspicious.obfuscation using app.setTimeOut to eval code',
'Run_Sploit' => 'suspicious.string -Run_Sploit-',
'HeapSpray' => 'suspicious.string -HeapSpray-', 
'var shellcode' => 'suspicious.string -shellcode-',
'C(.{0,6}?)o(.{0,6}?)l(.{0,6}?)l(.{0,6}?)a(.{0,6}?)b(.{0,6}?)c(.{0,6}?)o(.{0,6}?)l(.{0,6}?)l(.{0,6}?)e(.{0,6}?)c(.{0,6}?)t(.{0,6}?)E(.{0,6}?)m(.{0,6}?)a(.{0,6}?)i(.{0,6}?)l(.{0,6}?)I(.{0,6}?)n(.{0,6}?)f(.{0,6}?)o' => 'pdf.exploit Collab.collectEmailInfo CVE-2008-0655',
'Collab.collectEmailInfo' => 'pdf.exploit Collab.collectEmailInfo CVE-2008-0655',
'C(.{0,6}?)o(.{0,6}?)l(.{0,6}?)l(.{0,6}?)a(.{0,6}?)b(.{0,6}?)g(.{0,6}?)e(.{0,6}?)t(.{0,6}?)I(.{0,6}?)c(.{0,6}?)o(.{0,6}?)n' => 'pdf.exploit Collab.getIcon CVE-2009-0927',
'Collab.get(.{1,24}?)Icon' => 'pdf.exploit Collab.getIcon CVE-2009-0927',
'Collab.getIcon' => 'pdf.exploit Collab.getIcon CVE-2009-0927',
'util.printd' => 'pdf.suspicious util.printd used to fill buffers',
//'med(.*?)ia(.*?)newPlay(.*?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'med(.{1,24}?)ia(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'med(.{1,24}?)ia(.{1,24}?)newPlay(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'me(.{1,24}?)dia\.(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'me(.{1,24}?)dia\.(.{1,24}?)new(.{1,24}?)Play(.{1,24}?)er' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'Collab.collectEmailInfo' => 'pdf.exploit Collab.collectEmailInfo CVE-2008-0655',
'm(.{0,6}?)e(.{0,6}?)d(.{0,6}?)i(.{0,6}?)a(.{0,6}?)n(.{0,6}?)e(.{0,6}?)w(.{0,6}?)P(.{0,6}?)l(.{0,6}?)a(.{0,6}?)y(.{0,6}?)e(.{0,6}?)r' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'media(.{1,24}?)newPlayer' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'media.newPlayer' => 'pdf.exploit media.newPlayer CVE-2009-4324',
'spell(.{1,24}?)customDictionaryOpen' => 'pdf.exploit spell.customDictionaryOpen CVE-2009-1493',
'spell.customDictionaryOpen' => 'pdf.exploit spell.customDictionaryOpen CVE-2009-1493',
'util(.{1,24}?)printf(.{1,24}?)45000f' => 'pdf.exploit util.printf CVE-2008-2992',
'contentType=(.{0,6}?)image\/(.{0,30}?)CQkJCQkJCQkJCQkJCQkJCQkJ' => 'pdf.exploit using TIFF overflow CVE-2010-0188',
'exploit.tif' => 'suspicious.string TIFF overflow exploit.tif name CVE-2010-0188',
'kJCQ,kJCQ,kJCQ,kJCQ,kJCQ,kJCQ' => 'pdf.exploit using TIFF overflow CVE-2010-0188',
'JCQkJCQkJCQkJCQkJCQkJCQkJCQk' => 'suspicious.string base 64 nop sled used in TIFF overflow CVE-2010-0188',
'ImageField1(.{0,6}?)xfa:contentType=(.{0,6}?)image\/tif' => 'pdf.exploit TIFF overflow CVE-2010-0188',
'Launch/Type/Action/Win' => 'pdf.exploit exec action command',
'\/Action(.{0,24}?)\.exe' => 'pdf.execute exe file',
'\/Action(.{0,36}?)system32' => 'pdf.execute access system32 directory',
//'exportDataObject' => 'pdf.exploit accessing embedded files exportDataObject',
'Launch/Type/Action/Win' => 'pdf.exploit execute action command',
'M9090M9090M9090M9090' => 'suspicious.string obfuscated unicode NOP sled',
hex2bin('BB1500070003FE7FB27F0007BB15000711000100ACA80007BB15000700010100ACA80007F772000711000100E2520007545C0007FFFFFFFF000101000000000004010100001000004000000031D70007BB1500075A526A024D15000722A70007BB15000758CD2E3C4D15000722A70007BB150007055A74F44D15000722A70007BB150007B849492A4D15000722A70007BB150007008BFAAF4D15000722A70007BB15000775EA87FE4D15000722A70007BB150007EB0A5FB94D15000722A70007BB150007') => 'pdf.exploit TIFF overflow CVE-2010-0188',
//hex2bin('070000010300010000003020000001010300010000000100000003010300010000000100000006010300010000000100000011010400010000000800000017010400010000003020000050010300CC0000009220000000000000000C0C0824010100F772000704010100BB150007001000004D150007BB1500070003FE7FB27F0007BB15000711000100ACA80007BB15000700010100ACA80007F772000711000100E2520007545C0007FFFFFFFF000101000000000004010100001000004000000031D70007BB1500075A526A024D15000722A70007BB15000758CD2E3C4D15000722A70007BB150007055A74F44D15000722A70007BB150007B849492A4D15000722A70007BB150007008BFAAF4D15000722A70007BB15000775EA87FE4D15000722A70007BB150007EB0A5FB94D15000722A70007BB150007E00300004D15000722A70007BB150007F3A5EB094D15000722A70007BB150007E8F1FFFF4D15000722A70007BB150007FF9090904D15000722A70007BB150007FFFFFF904D15000731D700072F110007') => 'pdf.exploit TIFF overflow CVE-2010-0188',
'^FWS(.{1}?)' => 'suspicious.flash Embedded Flash',
'^CWS(.{1}?)' => 'suspicious.flash Embedded Flash',
'^SWF(.{1}?)' => 'suspicious.flash Embedded Flash',
hex2bin("0D0A43575309A2D20000789CECBD797C54") => 'suspicious.flash Embedded Flash',

'application#2Fx-shockwave-flash' => 'suspicious.flash Embedded Flash define obj',
'application/x-shockwave-flash' => 'suspicious.flash Embedded Flash define obj',
'SING(.{0,366}?)'.hex2bin('41414141414141414141') => 'pdf.exploit fontfile SING table overflow CVE-2010-2883 generic',

hex2bin('1045086F0000EB4C00000024686D747809C68EB20000B4C4000004306B65726EDC52D5990000BDA000002D8A6C6F6361F3CBD23D0000BB840000021A6D6178700547063A0000EB2C0000002053494E47D9BCC8B50000011C00001DDF706F7374B45A2FBB0000B8F40000028E70726570') => 'pdf.exploit fontfile SING table overflow CVE-2010-2883 A',

hex2bin('4657530947CB0000480140005A0000190100441108000000BF141CCB0000000000000010002E00060080804094A8D0A001808004100002000000121212E24130F00931343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134313431343134') => 'flash.exploit CVE-2011-0609',

hex2bin('7772697465427974650541727261799817343635373533304143433035303030303738') => 'flash.exploit CVE-2011-0611', 
hex2bin('5131645443737746414142346E453155625778545A52512B743733742B3362744B4E30596E617767552F414452654D5848334777597276757737597A643743674A734A6C76643174374E716D393959576D4B676B5A7674686C68446942556E344D694645453030514659306D456F664A2B4F45504D55594E6F69614C526D4E696A4D45494444665065652B3139663534652B35356E764F63383578376532766732514551504148514C6B45384248683175303937414B7741654943394F6A336579756277574E52793141564A475939326D4777444832794278794147636569424250524348') => 'flash.exploit CVE-2011-0611',
hex2bin('343635373533304143433035303030303738303030353546303030303046413030303030313830313030343431313030303030303030334630334137303530303030393630433030303530303037393543333743313330374642433337433133304531323944303230303443303439443032303031383030383831353030303930303431') => 'flash.exploit CVE-2011-0611',

hex2bin('076A69745F65676708') => 'flash.suspicious jit_spray', 
hex2bin('3063306330633063306330633063306306537472696E6706') => 'flash.exploit CVE-2011-0611', 
hex2bin('410042004300440045004600470048004900A18E110064656661756C74') => 'flash.exploit CVE-2011-0611', 
hex2bin('00414243444500566B6475686752656D686677317375727772777C73680064656661756C740067657453697A650047647768317375727772777C73680077777273757277') => 'flash.exploit CVE-2011-0611', 
//hex2bin('586D6C537766094D6F766965436C6970076A69745F656767086368696C64526566') => 'flash.exploit CVE-2011-0611', 
hex2bin('34363537353330394541433730303030373830303036343030303030304338303030303032443031303034343131313830303030303034333032463446344634383630363036303230303031303030304646303931303030303030303033303030313030383630363036303130303032303030303430303030303030424631313235') => 'flash.exploit CVE-2011-0609', 
hex2bin('3941303139413031394130313941303139064C6F61646572') => 'flash.exploit CVE-2011-0609', 
//hex2bin('537472696E6704434D594B094D6F766965436C6970076A69745F656767086368696C64526566') => 'flash.exploit CVE-2011-0611', 
'AAB4AAVfAAAPoAAAGAEARBEAAAAAPwOnBQAAlgwABQAHlcN8Ewf7w3wTDhKdAgBMBJ0CABgAiBUACQBBAEIAQwBEAEUARgBHAEgASQChjhEAZGVmYXVsdAABAAQqAAIAmAGWCgAHWMBJSAenP7a3YJ0CAAAAmQIASQBAlgUABxZ0cAtMYp0CAAwAhwEAAxeHAQABlgoAB' => 'flash.exploit CVE-2011-0611',

hex2bin('066F3A40AE366A4360DFCBEF8C38CA0492794B79E942BD2BB95B866065A4750119DACF6AF72A773CDEF1117533D394744A14734B18A166C20FDE3DED19D4322E') => 'pdf.exploit U3D CVE-2011-2462 A',

hex2bin('ED7C7938945DF8FF9985868677108DA58C922C612A516FA9D182374A8B868AA25284242D8A3296B497B74849D2A210D14EA94654A2452ACA2B29D18268A5B7C5EF7E') => 'pdf.exploit PRC CVE-2011-4369 A',
hex2bin("537472696E6706586D6C537766094D6F766965436C6970076A69745F656767086368696C645265660D446973706C61794F626A656374074D79566964656F05566964656F044D794E430D4E6574436F6E6E656374696F6E") => 'flash.exploit flash calling malformed MP4 CVE-2012-0754',
'(\&\#0*97;|a)(\&\#0*112;|p)(\&\#0*112;|p)(\&\#0*108;|l)(\&\#0*105;|i)(\&\#0*99;|c)(\&\#0*97;|a)(\&\#0*116;|t)(\&\#0*105;|i)(\&\#0*111;|o)(\&\#0*110;|n)(\&\#0*47;|\/)(\&\#0*120;|x)(\&\#0*45;|\-)(\&\#0*106;|j)(\&\#0*97;|a)(\&\#0*76;|v)(\&\#0*97;|a)(\&\#0*115;|s)(\&\#0*99;|c)(\&\#0*114;|r)(\&\#0*105;|i)(\&\#0*112;|p)(\&\#0*116;|t)(.{0,1}?)' => 'suspicious.javascript in XFA block',

hex2bin('6D703405566964656F0A6E6574436F6E6E6563740D4E6574436F6E6E656374696F6E096E657453747265616D094E657453747265616D') => 'flash.exploit MP4 Loader CVE-2012-0754 B',
hex2bin('6D70343269736F6D000000246D646174018080800E1180808009029F0F808080020001C0101281302A056DC00000000D63707274')  => 'flash.exploit MP4 CVE-2012-0754',

"push(.{1,5}?)xfa.datasets.createNode(.{1,5}?)dataValue"  => 'pdf.exploit Sandbox Bypass CVE-2013-0641',



);



	$PDFhexSearch = array(
'fb97fd0f' => 'shellcode.hash  CloseHandle',
'a517007c' => 'shellcode.hash  CreateFileA',
'72feb316' => 'shellcode.hash  CreateProcessA',
'25b0ffc2' => 'shellcode.hash  DeleteFileA',
'7ed8e273' => 'shellcode.hash  ExitProcess',
'efcee060' => 'shellcode.hash  ExitThread',
'aafc0d7c' => 'shellcode.hash  GetProcAddress',
'c179e5b8' => 'shellcode.hash  GetSystemDirectoryA',
'd98a23e9' => 'shellcode.hash  _hwrite',
'5b4c1add' => 'shellcode.hash  _lclose',
'ea498ae8' => 'shellcode.hash  _lcreat',
'8e4e0eec' => 'shellcode.hash  LoadLibraryA',
'db8a23e9' => 'shellcode.hash  _lwrite',
'f08a045f' => 'shellcode.hash  SetUnhandledExceptionFilter',
'add905ce' => 'shellcode.hash  WaitForSingleObject',
'98fe8a0e' => 'shellcode.hash  WinExec',
'1f790ae8' => 'shellcode.hash  WriteFile',
'e5498649' => 'shellcode.hash  accept',
'a41a70c7' => 'shellcode.hash  bind',
'e779c679' => 'shellcode.hash  closesocket',
'ecf9aa60' => 'shellcode.hash  connect',
'a4ad2ee9' => 'shellcode.hash  listen',
'b61918e7' => 'shellcode.hash  recv',
'a41970e9' => 'shellcode.hash  send',
'6e0b2f49' => 'shellcode.hash  socket',
'd909f5ad' => 'shellcode.hash  WSASocketA',
'cbedfc3b' => 'shellcode.hash  WSAStartup',
'361a2f70' => 'shellcode.hash  URLDownloadToFileA',
'9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090' => 'suspicious.shellcode NOP Sled');

$PDFblockHash = array(
'ea24ea1063f49c594f160a57c268d034' => 'flash.exploit CVE-2010-1297',
'8286cc6dc7e2193740f6413b6fc55c7e' => 'flash.exploit CVE-2010-1297',
'ac69d954d9e334d089927a1bc875d13d' => 'flash.exploit CVE-2010-1297',
'0ab61f2fe334e22b4defb18587ae019f' => 'flash.exploit CVE-2010-1297',
'49ddb9b210e773b987b9a25678f65577' => 'flash.exploit CVE-2010-1297',
'bd7eac5ae665ab27346e52278f367635' => 'flash.exploit CVE-2010-1297',
'4666a447105b483533b2bbd0ab316480' => 'flash.exploit CVE-2010-1297',
'8a4bb4b4b837aa1623fbb82938ba5100' => 'flash.exploit CVE-2010-1818',
'86293036e961af07c747f013d946301d' => 'flash.exploit CVE-2010-1297',
'86293036e961af07c747f013d946301d' => 'flash.exploit CVE-2009-1862',
'5e645fc4e7f7e3a21ba5127a8d2c2740' => 'flash.exploit CVE-2010-3654',
'8ff29ae0d2f2e8f44d82eda6b421f6eb' => 'flash.exploit CVE-2010-3654',
'069c8fe3bda864ad79e3f367f9fce3f7' => 'flash.exploit CVE-2010-3654',
'bda6a3ed554ce561f5e9b5e68b91959f' => 'flash.exploit CVE-2010-3654',
'346a67733ab9d0f7667a34565573780d' => 'flash.exploit CVE-2010-3654',
'ec79b58f58ad1225f1d97b15e4e775b8' => 'flash.exploit CVE-2010-3654',
'11ab584578571ba3c146353815823272' => 'flash.exploit CVE-2010-3639',
'8a4bb4b4b837aa1623fbb82938ba5100' => 'flash.exploit CVE-2010-2884',
'529ae8c6ac75e555402aa05f7960eb0d' => 'flash.exploit CVE-2010-2884', //vt
'0edf3454971c9deeb12d171a02b5d0a7' => 'flash.exploit JIT-spray', 
'5cdc4bb86c5d3b4338ad56a58f54491a' => 'flash.exploit JIT-spray', //vt
'40792ec6d7b7f66e71a3fdf2e58cb432' => 'flash.exploit CVE-2011-0609',//pdf 3d1fc4deb5705c750df6930550c2fc16
'00cf8b68cce68a6254b6206f250540fd' => 'flash.exploit CVE-2011-0609',
'b9da2f3987b2e958077f51c7feea54fa' => 'flash.exploit CVE-2011-2100 heapspray',//pdf 7ea84b62da84dcd8b6f577d670c86f68
'7cf3637aada1f0ed931f8796d92fd989' => 'flash.exploit CVE-2011-0611',
'97ff733a21bb0199caf07a84358d6349' => 'flash.exploit CVE-2011-0611',//pdf 9ead2b29d633bdac3b2cd4a16b2629a2
'ad92cb017d25a897f5b35e08b1707903' => 'flash.exploit CVE-2011-0611',
'ac8c381d95a9e4dc5d4532f691fe811d' => 'flash.exploit CVE-2011-0611',
'befbf2fed66de5cd04b6f998cdbdbab0' => 'flash.exploit CVE-2011-0611',
'7e9e040ee9bd1ab5aeb953a01fd1c689' => 'flash.exploit CVE-2011-0611',
'606d898f2267c2e29fd93b613532916c' => 'flash.exploit CVE-2011-0611',
'c56dd87772312ba032fc6ac8928d480f' => 'flash.exploit CVE-2011-0611',
'b17b606bbbaebc6373dd07c0f9cda809' => 'flash.exploit CVE-2011-0611',
'62974e97067c47fcd5ca26419d93cb88' => 'flash.exploit CVE-2011-0611',
'c93c03a7ad3da4e849379ad0a9569b60' => 'flash.exploit CVE-2011-0611',
'9da516f2d64987a2e1d0859e81544a6c' => 'flash.exploit CVE-2011-0611',
'2288f8fb599433b04188bf70a7d7df34' => 'flash.exploit CVE-2011-0611',
'e103fcc0ebfdda299dfda3c4dda34c7b' => 'pdf.exploit U3D CVE-2011-2462',
'e7a878f01517d6c5d742ac2243af9297' => 'pdf.exploit PRC CVE-2011-4369',

'1ab800674234fd3047e9fc7af6d2b8e3' => 'flash.exploit CVE-2011-0611',
'7f7536ece98a987aae362450b27a9061' => 'flash.exploit CVE-2011-0611',

'28a477a94807151fb757fa8601f7a77f' => 'flash.exploit CVE-2010-1297 msf',
'2d0a674b8920afb6ff90d1bd42d83415' => 'flash.exploit CVE-2010-3654 msf',
'b67eaf93669119733055fd7cd4c52496' => 'flash.exploit CVE-2011-0609 msf',
'86b6d302eb790c3780ef3fa79d72eefc' => 'flash.exploit CVE-2011-0611 msf',
'f709ccfb785d6280c37a3641fbb6f3f5' => 'flash.exploit CVE-2012-0754 msf',
'3a901db9dbcc2c6abfc916be7880400e' => 'flash.exploit MP4 Loader CVE-2012-0754 B',
'a04f6ef8693ad53d6c3115b7728a346b' => 'flash.exploit MP4 CVE-2012-0754',
);

function fuzzString($string) {
	$out = '';
	for($i=0; $i < strlen($string); $i++) {
		$out .= "(".$string[$i]."|#".dechex(ord($string[$i])).")";

	}
	return $out;
}


//object placeholders
$pdfobjTable = array('obj_id' => '', 'gen_id' => '', 'dup_id' => '', 'key' => '', 'md5_raw' => '', 'md5_decoded' => '',
		'filters' => '', 'params' => '', 'filename_raw' => '', 'filename_decoded' => '', 'size_raw' => '',
		'size_decoded' => '', 'exploit' => '', 'js' => '', 'embed_file' => '', 'encrypted' => '', 'otype' => '',
		'parent_md5' => '', 'parent_sha256' => '', 'aa' => '',  'params_decoded' => '', 'objstm' => '',
		'filename_uncompressed' => '', 'size_uncompressed' => '');


$pdfhitTable = array('obj_id' => '', 'gen_id' => '', 'dup_id' => '', 'parent_md5' => '', 'parent_sha256' => '', 'exploit' => '',
		'exploittype' => '', 'exploitlocation' => '', 'searchtype' => '', 'shellcode' => '',
		'engine' => '', 'block' => '', 'partial' => '', 'block_filename' => '', 'hid' => '', 'hrank' => '');

$pdfsampleTable = array('ip' => '', 'mw_url' => '', 'mw_ip' => '', 'mw_time' => '', 'hits' => '',
		'filename' => '', 'md5' => '', 'sha1' => '', 'sha256' => '',
		'filesize' => '', 'content-type' => '', 'searchtype' => '', 'exploit' => '', 'exploittype' => '',
		'exploitlocation' => '', 'ssdeep' => '', 'completed' => '', 'engine' => '', 'new'=> '',
		'encrypted' => '', 'key' => '', 'encrypt_alg' => '', 'key_length' => '',
		'email' => '', 'message' => '', 'is_malware' => '', 'severity' => '',
		'reported' => '', 'summary' => '', 'private' => '',
		'has_js' => '', 'has_flash' => '', 'has_embed' => '', 'origfilename' => '');


function charset($string) {
	$char = mb_detect_encoding($string, "GB2312, Big5, UTF-8, EUC-JP");
	if ($char != '') {
		$ascii = mb_convert_encoding($string, "ASCII", $char);
		return $ascii;
	}
	return $string;
}


function jsmakePretty($dirty)
{
	$str = '';
	$instring = -1;
	$incomment = -1;
	$incomment2 = -1;
	$stringChar = '';
	

	for ($i = 0; $i < strlen($dirty)-1; $i++) {
		if ( $incomment ==-1 && $incomment2 ==-1 && $instring == -1 && ($dirty[$i] == '\'' || $dirty[$i] == '"') ) {
			$instring = $i;
			//echo "In String [$i]\n";
			$str .= $dirty[$i];
			$stringChar = $dirty[$i];
		} else if ($incomment ==-1 && $incomment2 ==-1&& $instring >=0 && $i+1 <= strlen($dirty) && $dirty[$i] == "$stringChar" && $dirty[$i-1] != '\\' ) {
			$instring = -1;
			//echo "End String [$i]\n";
			$str .= $dirty[$i];
			$stringChar = '';
		} else if ($incomment ==-1 && $incomment2 ==-1&& $i+1 <= strlen($dirty) && $instring == -1 && ($dirty[$i] == '/' && $dirty[$i+1] == '/') ) {
			$incomment = $i;
			//echo "In Comment 1 [$i]\n";
			//$str .= $dirty[$i];
			$i++;
			//$str .= $dirty[$i];			
		} else if ($incomment ==-1 && $incomment2 ==-1&& $instring == -1 && ($dirty[$i] == '/' && $i+1 <= strlen($dirty) && $dirty[$i+1] == '*') ) {
			$incomment2 = $i;
			//echo "In Comment 2 [$i]\n";
			//$str .= $dirty[$i];
			$i++;
			//$str .= $dirty[$i];			
		} else if ($incomment2 >= 0 && ($dirty[$i] == '*' && $dirty[$i+1] == '/') && $i+1 <= strlen($dirty)) {
			$incomment2 = -1;
			$instring = -1;
			//echo "End comment 2 [$i]\n";
			//$str .= $dirty[$i];
			$i++;
			//$str .= $dirty[$i];			
			
		} else if ($incomment >= 0 && $dirty[$i] == "\n" ) {
			$incomment = -1;
			$instring = -1;
			//echo "End comment 1 [$i]\n";
			//$str .= $dirty[$i];
		} else if ($incomment >= 0 || $incomment2 >= 0) {
			//$str .= $dirty[$i];
		} else if ($incomment ==-1 && $incomment2 ==-1 && $instring == -1 && $dirty[$i] == ';' ) {
			$incomment = -1;
			//echo "add endline [$i]\n";
			$str .= $dirty[$i]."\n";;
 		} else if ($incomment ==-1 && $incomment2 ==-1 && $instring == -1 && $dirty[$i] == ' ' && $i+1 <= strlen($dirty) && ( $dirty[$i+1] == '{' ||
$dirty[$i+1] == '}' || $dirty[$i+1] == '(' || $dirty[$i+1] == ')' || $dirty[$i+1] == '=' || $dirty[$i+1] == '.' || 
$dirty[$i+1] == '\'' || $dirty[$i+1] == '"' || $dirty[$i+1] == '+' || $dirty[$i+1] == ' ')  ) {
			//$str .= $dirty[$i]."\n";
			//echo "test\n";
 		} else if ($incomment ==-1 && $incomment2 ==-1 && $instring == -1 && $dirty[$i] == ' ' && $i >= 1 &&( $dirty[$i-1] == ' ' || $dirty[$i-1] == '{' ||
$dirty[$i-1] == '}' || $dirty[$i-1] == '(' || $dirty[$i-1] == ')' || $dirty[$i-1] == '=' ||
$dirty[$i-1] == '\'' || $dirty[$i-1] == '"' || $dirty[$i-1] == '.' || $dirty[$i-1] == '+') ) {
			//$str .= $dirty[$i]."\n";;
		} else {
			$str .= $dirty[$i];
		}

	}

$arr = explode("\n", $str);
$str = '';
foreach ($arr as $line) {
	if ($line != '')
		$str .= trim($line)."\n";

};




  return $str;
}


function is_js($string) {

	//$str = jsmakePretty($string);
	$str = $string;


	$level = 0;
	$arr = explode(";\n", $str);
	$str = '';
	//$variables = array();
	foreach ($arr as $line) {
		$line = trim($line);
		if (strstr($line, '=') && strstr($line, 'var ') ) {
			//$arr2 = explode("=", $line, 2);
			//	echo "var = ".$arr2[0]."\n";
			//	echo "val = ".$arr2[1]."\n";
				
			//	$variables[str_replace('var ', '', $arr2[0])] = $arr2[1];
			$level++;
			//echo "var\n";
		} else if (preg_match("/function(\s*?)([a-zA-Z0-9_-]*?)(\s{0,25}?)\(/i", $line)) {
			$level++;
			//echo "funct\n";
		} else if (preg_match("/return /i", $line)) {
			$level++;
			//echo "return\n";
		} else if (preg_match("/try(\s*?)\{/i", $line)) {
			$level++;
			//echo "try\n";
		} else if (preg_match("/catch(\s*?)\{/i", $line)) {
			$level++;
			//echo "catch\n";
		} else if (preg_match("/replace(\s{0,3}?)\(/i", $line)) {
			$level++;
			//echo "replace\n";
		} else if (preg_match("/new Array/", $line)) {
			$level++;
			//echo "array\n";
		} else if (preg_match("/new Object/", $line)) {
			$level++;
			//echo "obj\n";
		} else if (preg_match("/new String(\s{0,3}?)\(/", $line)) {
			$level++;
			//echo "string\n";
		} else if (preg_match("/charAt(\s{0,3}?)\(/", $line)) {
			$level++;
			//echo "charat\n";
		} else if (preg_match("/^([a-zA-Z0-9_-]+?)=([a-zA-Z0-9_-]+?);$/", $line)) {
			$level++;
			//echo "format\n";
		} else if (preg_match("/substr(\s{0,3}?)\(/", $line)) {
			$level++;
			//echo "substr\n";
		} else if (preg_match("/app.viewerVersion/", $line)) {
			$level++;
			//echo "view\n";

		}
	}


	//var_dump($variables);

	return $level;
}


function scanStreams($result, $obj, $gen) {
	foreach ($result as $unique => $data) {
		if (isset($data['objstm']) && $data['objstm'] > 0) {
			if ((preg_match("/\/(#4a|J)(#61|a)(#76|v)(#61|a)(#53|S)(#63|c)(#72|r)(#69|i)(#70#p)(#74|t)\s+".$obj."\s+".$gen."\s+R/si", $data['parameters'])  ||  preg_match("/\/(#4a|J)(#53|S)\s+".$obj."\s+".$gen."\s+R/s", $data['parameters']))) {
				return 1;
			}
		}
	}
	return 0;
}

function analysePDF($file = array(), $sample_id = 0) {
	global $PDFstringSearch, $PDFhexSearch, $global_block_encoding, $global_engine, $pdfdir, $global_store_files, $global_export_all, $global_yara_sig;

	$md5 = $file['md5'];

	logDebug($file['md5']." start processing");

	$file_raw = file_get_contents($file['filename']);
	logDebug($file['md5']." end processing");

	$yara_result = array();


	$fileUpdate = array('exploit' => 0, 'hits' => 0, 'completed' => 1, 'is_malware' => 0, 'summary' => '', 'severity' => 0);


	$header = substr($file_raw, 0, 1024);
	if (preg_match("/ns.adobe.com\/xdp/si", $header)) {
		//process xdp format
		preg_match("/<chunk>(.*?)<\/chunk>/si", $file_raw, $matchF);
		if (isset($matchF[1])) {
			$intermediate = base64_decode($matchF[1]);
			if ($intermediate != '')
				$file_raw = $intermediate;
		}

	}
	$header = substr($file_raw, 0, 1024);
	if (!preg_match("/%PDF/si", $header)) {
		echo "File missing PDF signature - not processed.\n";
		$fileUpdate['not_pdf'] = 1;
		return $fileUpdate;
	}



	//yara original file
	if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
		$yhits = yara_wrapper_file($file['filename']);
		foreach ($yhits as $k => $v) {
			array_push($yara_result, $k);
		}
	}


	$result = pdfSlice($file_raw);



	//store encryption metadata
	if (isset($result['document']['encrypted']) && $result['document']['encrypted'] > 0) {
		$fileUpdate['encrypted'] = 1;
		$fileUpdate['key'] = $result['document']['key'];
		//if ($result['document']['v'] == 4)
			$fileUpdate['encrypt_alg'] = $result['document']['v'];
		//else
			//$fileUpdate['encrypt_alg'] = "RC4";
		$fileUpdate['key_length'] = $result['document']['key_length'];

	}


	$summaryA = array();

	//objstm section
	$newobjs = array();
	foreach ($result as $unique => $data) {
		if ($unique != 'document') {
			if (isset($data['parameters']) && preg_match("/(#4F|O)(#62|b)(#6a|j)(#53|S)(#74|t)(#6d|m)/si", $data['parameters']) ) {
				//check for ObjStm
				$data['otype'] = "ObjStm";
				$newobj = parseObjStm($data['parameters'], $data['decoded']);
				foreach ($newobj as $uniquel => $datal) {
					$datal['objstm'] = $data['object'];
					$datal['dup_id'] += $data['dup_id'];
					$datal['atype'] = "objstm";
					$result[$uniquel] = $datal;
				}
				//print_r( $newobj);
				
				//$newobjs = array_merge($newobjs, $newobj);
				//print_r($newobjs);
			}
		}
	}
	//$result = array_merge($result, $newobjs);
	//print_r($result);
	//objstm  endsection

	foreach ($result as $unique => $data) {

		if ($unique != 'document') {


			//scan for malware


			$malware = array('found' => 0);
			

			logDebug($file['md5']."obj ".$data['object']." raw");

			$d = '';
			if (isset($data['decoded']))
				$d = $data['decoded'];

			//uncompress flash
			if (preg_match("/^CWS(.{1}?)/s", $d)) {
				$uncompressed = flashExplode($d);
				$unmd5 = md5 ($uncompressed);
				if ($uncompressed != '') {
					if (!isset($global_store_files) || $global_store_files != 0) {
						if (!file_exists($pdfdir.$file['md5']."/"))
							mkdir($pdfdir.$file['md5']."/");
						file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$unmd5.".flash", $uncompressed);
						$data['filename_uncompressed'] = $pdfdir.$file['md5']."/".$unmd5.".flash";
					}
					$data['size_uncompressed'] = strlen($uncompressed);
				}

				$malware = javascriptScan($malware, $uncompressed, $PDFstringSearch, $PDFhexSearch);
				if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '')  ) {
					$malware['javascript'] = $uncompressed;
							
				}



				//yara exploded flash
				if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
					$yhits = yara_wrapper($uncompressed );
					foreach ($yhits as $k => $v) {
						array_push($yara_result, $k);
					}
				}



			}


			//original
			$malware = javascriptScan($malware, $d, $PDFstringSearch, $PDFhexSearch);
			if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '')  ) {
				$malware['javascript'] = $d;
							
			}


			//yara decoded objects
			if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
				$yhits = yara_wrapper($d);
				foreach ($yhits as $k => $v) {
					array_push($yara_result, $k);
				}
			}



			//correct for unicode
			//$d = charset($d);
			$d = str_replace("\x00", "", $d); //turf unicode here

			$malware = javascriptScan($malware, $d, $PDFstringSearch, $PDFhexSearch);
			if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '')  ) {
				$malware['javascript'] = $d;
							
			}

			//correct for hexcodes
			$df = findHiddenJS($d);
			logDebug($file['md5']."obj ".$data['object']." hex");
										
			$malware = javascriptScan($malware, $df, $PDFstringSearch, $PDFhexSearch);
			if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '') ) {
				$malware['javascriptencoding'] = $global_block_encoding;
			}
				
			logDebug($file['md5']."obj ".$data['object']." unicode");
				

			//correct for unicode			
			$df = decode_replace($d);
			$df = unicode_to_shellcode($df);
			//echo "JSEnc2: $df\n";
			$malware = javascriptScan($malware, $df, $PDFstringSearch, $PDFhexSearch);
			if ($malware['found'] >= 1 && (!isset($malware['javascript']) || $malware['javascript'] == '') ) {
				$malware['javascript'] = $df;
			}

			logDebug($file['md5']."obj ".$data['object']." blocks");


			//blockhashes for flash etc
			if (isset($data['md5_raw'])) {
				$ret = checkBlockHash($data['md5_raw']);
				if ($ret['found'] == 1) {
					$malware = array_merge($ret, $malware);
					//echo "blocka\n";
					$malware['found'] = 1;
				} else if (isset($data['md5'])) {
					$ret = checkBlockHash($data['md5']);
					if ($ret['found'] == 1) {
						$malware = array_merge($ret, $malware);
						//echo "blockb\n";
						$malware['found'] = 1;
					}
				}
			} else if (isset($data['md5'])) {
				$ret = checkBlockHash($data['md5']);
				if ($ret['found'] == 1) {
					$malware = array_merge($ret, $malware);
					//echo "blockc\n";
					$malware['found'] = 1;
				}
			}

			logDebug($file['md5']."obj ".$data['object']." params");


			//run scan on params for colors overflow etc
			if (isset($data['parameters']) && $data['parameters'] != '') {
				$malware = javascriptScan($malware, $data['parameters'], $PDFstringSearch, $PDFhexSearch);

				if (isset($result['document']['encrypted'])) {
					//yara decrypted params
					if (isset($global_yara_sig) && is_readable($global_yara_sig)) {
						$yhits = yara_wrapper($data['parameters']);
	
						foreach ($yhits as $k => $v) {
							array_push($yara_result, $k);
						}
					}


				}

			}

			
			$pdfobj = array('obj_id' => $data['object'], 'gen_id' => $data['generation'],
				'params' => $data['parameters'], 'dup_id' => $data['dup_id'],
				'parent_md5' => $file['md5'], 'parent_sha256' => $file['sha256']);

			if (isset($data['filename_uncompressed']) ) {
				$pdfobj['filename_uncompressed'] = $data['filename_uncompressed'];
				$pdfobj['size_uncompressed'] = $data['size_uncompressed'];


			}

			logDebug($file['md5']."obj ".$data['object']." save hits");



			if ($malware['found'] >= 1) {
				$pdfobj['exploit'] = 1;
				$fileUpdate['exploit'] = 1;
				$fileUpdate['hits']++;
				foreach ($malware as $search => $hitraw) {
					if(is_array($hitraw)) {
						//echo $hitraw['virustype'];
						$hit = array('obj_id' => $data['object'], 'gen_id' => $data['generation'], 'dup_id' => $data['dup_id'],
							'parent_md5' => $file['md5'], 'parent_sha256' => $file['sha256'], 'exploit' => 1,
							'exploittype' => $hitraw['virustype'], 'exploitlocation' => $hitraw['location'], 											'searchtype' => $hitraw['searchtype'],
							'engine' => $global_engine, 'block' => $hitraw['block']);
						if (stristr($hitraw['block_type'], 'shellcode')) 
							$hit['shellcode'] = 1;
						/*if (stristr($hitraw['block_type'], 'javascript')) //hits on flash as well
							$pdfobj['js'] = 1;*/
						if (isset($hitraw['rawblock']))
							$hit['partial'] = $hitraw['rawblock'];
						
						if (stristr($hitraw['virustype'], 'javascript in XFA block') )
							$pdfobj['js'] = 1;

						if (stristr($hitraw['virustype'], 'CVE-')  && !stristr($hitraw['virustype'], 'CVE-2009-0658') )
							$fileUpdate['severity'] += 10;
						else
							$fileUpdate['severity'] += 1;


						//$fileUpdate['summary'] .= $hit['obj_id'].".".$hit['gen_id']."@".$hit['exploitlocation'].": ".$hit['exploittype']."\n";
						$summaryA[$hit['obj_id'].".".$hit['gen_id']."@".$hit['dup_id'].$hit['exploittype']] = $hit['obj_id'].".".$hit['gen_id']."@".$hit['dup_id'].": ".$hit['exploittype']."\n"; 
					}
				}
			}


			
				


			if (isset($data['key']))
				$pdfobj['key'] = $data['key'];
			if (isset($data['filter']))
				$pdfobj['filters'] = $data['filter'];
			if (isset($data['atype']) && $data['atype'] == 'js')
				$pdfobj['js'] = 1;
			if (!isset($pdfobj['js']) && isset($data['decoded'])) {
				$dat = str_replace("\x00", "", $data['decoded']);
				//echo $data['object']."\n";
				$level = is_js($dat);
				if ($level > 1)
					$pdfobj['js'] = $level;
			}


			if (!isset($pdfobj['js']) &&  (preg_match("/\/(#4a|J)(#61|a)(#76|v)(#61|a)(#53|S)(#63|c)(#72|r)(#69|i)(#70#p)(#74|t)\s+".$data['object']."\s+".$data['generation']."\s+R/si", $file_raw)  ||  preg_match("/\/(#4a|J)(#53|S)\s+".$data['object']."\s+".$data['generation']."\s+R/s", $file_raw))) {
				$pdfobj['js'] = 1;
			}

			if (!isset($pdfobj['js']) &&  preg_match("/\/(#4a|J)(#53|S)\s+\(/s", $data['parameters']) ) {
				$pdfobj['js'] = 1;
			}

			if (!isset($pdfobj['js']) && scanStreams($result, $data['object'], $data['generation']) == 1)
				$pdfobj['js'] = 1;


			if (isset($data['parameters']) && preg_match("/(#61|a)(#70|p)(#70|p)(#6c|l)(#69|i)(#63|c)(#61|a)(#74|t)(#69|i)(#6f|o)(#6e|n)\s*(#2F|\/)\s*(#70|p)(#64|d)(#66|f)/si", $data['parameters']) ) {
				//should grab the embedded pdf
				$pdfobj['embed_file'] = 1;
				logDebug($file['md5']."obj ".$data['object']." has embedded pdf");

			} //could do alt check for embedded pdfs with header


			if (isset($data['otype']) && $data['otype'] != '')
				$pdfobj['otype'] = $data['otype'];


			if (isset($data['parameters']) && preg_match("/(#4F|O)(#62|b)(#6a|j)(#53|S)(#74|t)(#6d|m)/si", $data['parameters']) ) {
				//check for ObjStm
				$pdfobj['otype'] = "ObjStm";
			}
			



			if (isset($result['document']['encrypted'])) {
				$pdfobj['encrypted'] = $result['document']['encrypted'];

			} else
				$pdfobj['encrypted'] = 0;

			if (isset($data['stream']) && $data['stream'] != '') {
				$pdfobj['md5_raw'] = $data['md5_raw'];
				if (!isset($global_store_files) || $global_store_files != 0) {
					if (!file_exists($pdfdir.$file['md5']."/"))
						mkdir($pdfdir.$file['md5']."/");
					file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$data['md5_raw'].".stream", $data['stream']);
					$pdfobj['filename_raw'] = $pdfdir.$file['md5']."/".$data['md5_raw'].".stream";
				}
				$pdfobj['size_raw'] = strlen($data['stream']);
			}

			if (isset($data['decoded']) && $data['decoded'] != '') {
				$pdfobj['md5_decoded'] = $data['md5'];
				if (!isset($global_store_files) || $global_store_files != 0) {
					if (!file_exists($pdfdir.$file['md5']."/"))
						mkdir($pdfdir.$file['md5']."/");
					file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$data['md5'].".stream", $data['decoded']);
				}
				$pdfobj['filename_decoded'] = $pdfdir.$file['md5']."/".$data['md5'].".stream";
				$pdfobj['size_decoded'] = strlen($data['decoded']);
			}


			//process embedded PDF
			if (isset($pdfobj['embed_file']) && $pdfobj['embed_file'] == 1) {
				if (isset($data['decoded']) && $data['decoded'] != '') {
					logDebug($file['md5']."obj ".$data['object']." check pdf header");
					if (preg_match("/%PDF/si", $data['decoded'])) {
						logDebug($file['md5']."obj ".$data['object']." run embedded ".$pdfobj['filename_decoded']);

						//$sub = ingest($pdfobj['filename_decoded']);
						if (isset($sub['severity']))
							$fileUpdate['severity'] += $sub['severity'];
					}

				}

			}


			if (isset($pdfobj['js']) && $pdfobj['js'] > 0)
				$fileUpdate['severity'] += 1;


			if ($fileUpdate['severity'] > 0)
				$fileUpdate['is_malware'] = 1;

			if (isset($pdfobj['js']) && $pdfobj['js'] > 0)
				$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."js"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: object contains JavaScript\n";

			if (isset($pdfobj['embed_file']) && $pdfobj['embed_file'] == 1) 
				$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."pdf"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: object contains embedded PDF\n";


			if (isset($pdfobj['size_raw']) && isset($pdfobj['size_decoded']) && $pdfobj['size_raw'] > 0 && $pdfobj['size_decoded'] == 0) 
				$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."dc"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: object not decoded\n";



			logDebug($file['md5']."obj ".$data['object']." end");

		}
		
	}

	//grab EOF
	logDebug($file['md5']."obj extract eof ");

	if (preg_match_all("/(\x25\x25EOF)/s", $file_raw, $matches, PREG_OFFSET_CAPTURE) ) {
		$occ = count($matches[0]);
		$lastloc = $matches[0][$occ-1][1]+5;
		$enddata = trim(substr($file_raw, $lastloc), "\x0A\x0D");
		if ($enddata != '' ) {

		
			logDebug($file['md5']."obj extract eof 2");

	
				$pdfobj = array('obj_id' => -1, 'gen_id' => -1,
					'params' => 'Extracted from end of file', 'dup_id' => $lastloc,
					'parent_md5' => $file['md5'], 'parent_sha256' => $file['sha256']);
				$pdfobj['md5_raw'] = md5($enddata);
				if (!isset($global_store_files) || $global_store_files != 0) {
					if (!file_exists($pdfdir.$file['md5']."/"))
						mkdir($pdfdir.$file['md5']."/");
					file_put_contents($pdfdir.$file['md5']."/obj-".$data['object']."-gen-".$data['generation']."-dup-".$data['dup_id']."-".$pdfobj['md5_raw'].".stream", $enddata);
					$pdfobj['filename_raw'] = $pdfdir.$file['md5']."/".$pdfobj['md5_raw'].".stream";
				}
					$pdfobj['size_raw'] = strlen($enddata);


				if ($pdfobj['obj_id']== -1 && $pdfobj['size_raw'] > 128) 
					$summaryA[$pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id']."ss"] = $pdfobj['obj_id'].".".$pdfobj['gen_id']."@".$pdfobj['dup_id'].": suspicious.warning: end of file contains content\n";



				logDebug($file['md5']."obj save eof ");
		
		}

	}	


	foreach ($summaryA as $key => $value) {
		$fileUpdate['summary'] .= $value;
	}


	$fileUpdate['engine'] = $global_engine;

	if (isset($global_export_all) && $global_export_all == 1)
		$fileUpdate['export_all'] = $result;


	if (count($yara_result) > 0)
		$fileUpdate['yara'] = array_unique($yara_result);

	return $fileUpdate;
		
}


function parseObjStm($params, $stream) {
	$n = 0;
	$out = array();

	if (preg_match("/(#4E|N)\s+(\d+)/s", $params, $res) ) {
		
		$n = $res[2];
		//echo "N=$n\n";
	}


	$first = 0;
	if (preg_match("/(#46|F)(#69|i)(#72|r)(#73|s)(#74|t)\s+(\d+)/s", $params, $res2) ) {
		
		$first = $res2[6];
		//echo "First=$first\n";
	}

	$header = substr($stream, 0, $first-1);
	//echo "Header=$header\n";

	preg_match_all("/(\d+)\s+(\d+)/s", $header, $resh);

	//print_r($resh);
	if(isset($resh[1]) ) {
		for ($i=0; $i < count($resh[1]); $i++) {
			//echo "Obj=".$resh[1][$i]." loc=".($resh[2][$i]+$first);
			if ($i+1 >= count($resh[1])) {
				$end = strlen($stream);
				//echo " End=".$end;
			} else {
				$end = $resh[2][$i+1]+$first-1;
				//echo " End=".$end;
			}
				
			//echo "\n";
			$ident = $resh[1][$i].".0.".($resh[2][$i]+$first);
			$out[$ident] = array('object' =>  $resh[1][$i], 'generation' => '0', 'obj_id' =>  $resh[1][$i], 'gen_id' => '0', 'dup_id' => ($resh[2][$i]+$first));


			//split params and stream
			$out[$ident]['parameters'] = substr($stream, $resh[2][$i]+$first, $end-$resh[2][$i]-$first);
		}

	}
	
	return $out;
}




function mtyara($filename, $signature_file) {
	global $global_yara_cmd;

	exec("$global_yara_cmd ".escapeshellarg($signature_file)." ".escapeshellarg($filename).' 2>&1', $out);

	$yara_result = array();
	$current_rule = '';
	$error = '';

	foreach ($out as $line) {
	
		if (substr($line, 0, 2) == "0x") {
			preg_match("/^0x([\da-fA-F]+):.(\w+): (\w+)$/",$line, $matches);
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
	global $global_yara_sig,$pdfdir;

	$tmp_file = "$pdfdir"."mwtcrtmyara-".uniqid();
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

if (!isset($PDFstringSearch)) {
	echo "ERROR: Signatures not found. mt-pdfsig.php is probably corrupt.\n";
	exit(0);
}


if (!isset($argv[1])) {
	echo "Please specify a file or directory to process\n";
	exit(0);
}



$options = getopt("p:y:v", array("yara:", "yarasig:","version","info","password:"));

if (isset($options['p']))
	$global_userpass = $options['p'];
if (isset($options['password']))
	$global_userpass = $options['password'];

if (isset($options['y']) )
	$global_yara_sig = $options['y'];
if (isset($options['yarasig']) )
	$global_yara_sig = $options['yarasig'];
if (isset($options['yara']) )
	$global_yara_cmd = $options['yaracmd'];
if (isset($options['version']) || isset($options['v']) || isset($options['info'])) {
	echo "pdfex.php <-y yarasig> <-p decryp pass> <file or dir>\n";
		if (!isset($global_engine) ) {
			echo "ERROR: Signatures not found.\n";
			exit(1);
		} 
		echo "Detection engine: $global_engine\n";
		echo "PDF string signatures: ".count($PDFstringSearch)."\n";
		echo "PDF hex signatures: ".count($PDFhexSearch)."\n";
		echo "PDF object hashes: ".count($PDFblockHash)."\n";
}

$file = array();
$dir = array();
$opt = array();
for ($i = 1; $i < $argc; $i++) {
	if ($argv[$i] == "-y" || $argv[$i] == "-v" || $argv[$i] == "--version" || $argv[$i] == "--info" ||$argv[$i] == "--yara") {
		$i++;
	} else if (is_file($argv[$i])) {
		$file[$argv[$i]] = 1;
	} else if (is_dir($argv[$i])) {
		$dir[$argv[$i]] = 1;
	} else
		$opt[$argv[$i]] = 1;
}




function malware_analysis_pdf($f){
	
	$filedat = array ('filename' => $f, 'md5' => md5_file($f), 'sha256' => '');

	$result = analysePDF($filedat);

	if (isset($result['yara']) && is_array($result['yara'])) {
		$yara = '';
		foreach($result['yara'] as $sig) {
			if ($sig != '')
				$yara .= "$sig\n";
		}
		$result['yara'] = $yara;
	}
			

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
				
		$json_res = json_encode($result);
		echo $json_res;		
	}
}


//malware_analysis($argv[1]);



//optional debugging handlers
function logdebug($string) {
	//echo $string."\n";
}
function logverbose($string) {
	//echo $string."\n";
}

?>
