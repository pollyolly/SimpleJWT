<?php
class SimpleJWT {

    //create token
    public function token($array){
        $header = base64_encode(json_encode($array['header']));
        $payload = base64_encode(json_encode($array['payload']));
        $hp = $header.'.'.$payload;
        $sign = base64_encode($this->hash_key($hp));
        $token = $header.'.'.$payload.'.'.$sign;
        return $token;
    }
    //verify received token
    public function verify_token($token){
        $tdata = explode('.', $token);
        $theader = $tdata[0];
        $tpayload = $tdata[1];
        $tsign = $tdata[2];
        $thp = $theader.'.'.$tpayload;
        $sign = base64_encode($this->hash_key($thp));
        return hash_equals($sign, $tsign);
    }
	//return if cookie exists in your browser
    public function verify_cookietoken($token){
        $ctokenID = isset($_COOKIE['_Secure-Fgp_']) ? $_COOKIE['_Secure-Fgp_'] : $_COOKIE['_Secure-Fgp_'];
        $payload = $this->extract_paypload($token);
        return $payload->ctokenID === $ctokenID ? true : false;
    }
    //return objects for header
    public function extract_header($token){
        $tdata = explode('.', $token);
        $theader = base64_decode($tdata[0]);
        return json_decode($theader);
    }
    //return objects for payload
    public function extract_payload($token){
        $tdata = explode('.', $token);
        $tpayload = base64_decode($tdata[1]);
        return json_decode($tpayload);
    }
    //return true if expired
    public function check_expiration($token){
        $tdata = explode('.', $token);
        $payload = $this->extract_paypload($token);
        return strtotime('now') > strtotime($payload->expiresAt) ? true : false;
    }
    //hash data with hashed key
    //default false to return hashed value
    public function hash_key($data){
        $key_path= realpath(__DIR__).'\/';
        $key = file_get_contents($key_path.'key.txt');
        return hash_hmac('sha256', $data, $key);
    }
    //you may use this to encrypt/decrypt sensive key=>value in payload
    public function ende_cryption($data, $action){
	    	$key = '';
	   	if(function_exists('openssl_cipher_iv_length')){
			switch($action){
				case 'encrypt':
					$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
					$iv = openssl_random_pseudo_bytes($ivlen);
					$ciphertext_raw = openssl_encrypt($data, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
					$hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
					$ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
					return $ciphertext;
				case 'decrypt':
					$c = base64_decode($data);
					$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
					$iv = substr($c, 0, $ivlen);
					$hmac = substr($c, $ivlen, $sha2len=32);
					$ciphertext_raw = substr($c, $ivlen+$sha2len);
					$original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
					$calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
					if (hash_equals($hmac, $calcmac))//timing attack safe comparison
					{
					    return $original_plaintext;
					}
			}
    		} else { echo 'OpenSSL Not Installed!'; exit; }
    }
    //generate random issuerid
    public function random_issuerid(){
        $randomString = time().uniqid('_riss_', true);
        $hashid = hash('sha256', $randomString);
        return $hashid;
    }
    //set cookie token upon login
    public function random_cookietoken(){
        $randomString = time().uniqid('_rct_', true);
        $hashid = hash('sha256', $randomString);
        $secFingerprint = '_Secure-Fgp_='.$hashid.';SameSite=Strict;HttpOnly;';
        header('Set-Cookie:'.$secFingerprint);
        return $hashid;
    }
}
$sjwt = new SimpleJWT();
/*$array = array(
     'header' => array(
             'typ' => 'JWT',
             'algo' => 'sha256'
     ),
     'payload' => array(
             'issuerID' => $sjwt->random_issuerid(),
             'ctokenID' => $sjwt->random_cookietoken(),
             'issuedAt' => date('Y-m-d h:m:sa', strtotime('now')),
             'notBefore' => date('Y-m-d h:m:sa', strtotime('now')),
             'expiresAt' => date('Y-m-d h:m:sa', strtotime('+1 day', strtotime('now')))
     )
 );*/
/**
 * Generate Token
 */
/*$token = $sjwt->token($array);
 echo $token;*/
//$token = "eyJ0eXAiOiJKV1QiLCJhbGdvIjoic2hhMjU2In0=.eyJpc3N1ZXJJRCI6IjM2ZDcwMmQxOThiMjgwMDdiOTE0NmMzZTVmOGVkN2ZhNDk5ZGIyNmZkNDRlNDQ5YTdhYmQ4ZmQxNThkNTZkZjUiLCJjdG9rZW5JRCI6ImMyM2JlMjU3ZjE3Y2FjNmY4OWNlYWU0YTljNjZmN2U4MDFhOTNiNmNjMDJjY2Q3N2NmZTUwNzc2MzA5YTAxZjYiLCJpc3N1ZWRBdCI6IjIwMTgtMDktMTEgMTI6MDk6MzhwbSIsIm5vdEJlZm9yZSI6IjIwMTgtMDktMTEgMTI6MDk6MzhwbSIsImV4cGlyZXNBdCI6IjIwMTgtMDktMTIgMTI6MDk6MzhwbSJ9.NmQ0ZTgxODE5NGRkNGMxMDgxN2VhNjQ4NTgxYjdmOWNmODc5MDA4YmFmMTY3OGQwZTg3ZDA4NzBjN2I3YzVhMw==";
// echo $sjwt->hash_key('sample', FALSE);
/**
 * Check 
 * Expiration Token
 */
// if(@$sjwt->check_expiration($token)){
//     echo "Expired \n";
// } else { 
//     echo "Not Expired \n";
//  }
/**
 * Check 
 * Verify Token
 */
/*if(@$sjwt->verify_token($token)){
    echo "Verified token! \n";
//    var_dump($sjwt->extract_payload($token));
    if(@$sjwt->verify_cookietoken($token)){
        echo "Verified cookie token! \n";
    }
} else {
    echo "Verification failed! \n"; 
}*/
//echo $sjwt->ende_cryption('', 'decrypt');
