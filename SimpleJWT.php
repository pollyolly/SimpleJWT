<?php
class SimpleJWT {
    //create token
    public function token($array, $secret){    
        $header = base64_encode(json_encode($array['header']));
        $payload = base64_encode(json_encode($array['payload']));
        $hp = $header.".".$payload;
        $sign = base64_encode(hash('sha256',$hp.$secret));
        $token = $header.'.'.$payload.'.'.$sign;
        return $token;
    }
    //verify received token
    public function verify_token($token, $secret){
        $tdata = explode('.', $token);
        $theader = $tdata[0];
        $tpayload = $tdata[1];
        $tsign = $tdata[2];
        $thp = $theader.".".$tpayload;
        $sign = base64_encode(hash('sha256',$thp.$secret));
        return $sign == $tsign ? true : false;
    }
    //return objects for header
    public function extract_header($token){
        $tdata = explode('.', $token);
        $theader = base64_decode($tdata[0]);
        return json_decode($theader);
    }
    //return objects for payload
    public function extract_paypload($token){
        $tdata = explode('.', $token);
        $tpayload = base64_decode($tdata[1]);
        return json_decode($tpayload);
    }
    //return true if expired
    public function check_expiration($token){
        $tdata = explode('.', $token);
        $payload = $this->extract_paypload($token);
        return strtotime("now") > strtotime($payload->expiration) ? true : false;
    }
}
$array = array(
    'header' => array(
            'typ' => 'JWT',
            'algo' => 'sha256'
    ),
    'payload' => array(
            'issuer' => 'from DNS',
            'issuedAt' => date('Y-m-d h:m:sa', strtotime("now")),
            'expiration' => date('Y-m-d h:m:sa', strtotime("+1 day", strtotime("now"))),
            'audience' => 'to DNS',
            'subject' => 'user name of token (optional)'
    )
);
$secret = '$$secreteKey$$%156.';
$sjwt = new SimpleJWT();
/**
 * Generate Token
 */
// $token = $sjwt->token($array, $secret);
// echo $token;

/**
 * Check 
 * Expiration Token
 */
$token = "eyJ0eXAiOiJKV1QiLCJhbGdvIjoiaGFzaGVkIn0=.eyJpc3N1ZXIiOiJmcm9tIEROUyIsImlzc3VlZEF0IjoiMjAxOC0wOC0yNiAxMDowODoyNmFtIiwiZXhwaXJhdGlvbiI6IjIwMTgtMDgtMjcgMTA6MDg6MjZhbSIsImF1ZGllbmNlIjoidG8gRE5TIiwic3ViamVjdCI6InVzZXIgbmFtZSBvZiB0b2tlbiAob3B0aW9uYWwpIn0=.NzE1ZjUzYjQzNWZkY2FjYzVhYzYzMDk4MTFjYzQ2MWQxMmU5ZDU5ZWE4ODc1OTVkOGI0NjMwYWEwOTg4ZjAzYQ==";
if(@$sjwt->check_expiration($token)){
    echo "Expired \n";
} else { echo "Not Expired \n"; }

/**
 * Check 
 * Verify Token
 */
if(@$sjwt->verify_token($token, $secret)){
    echo "Verified token! \n";
} else { echo "Verification failed! \n"; }