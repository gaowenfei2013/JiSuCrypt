<?php

require_once("crypto/JiSuCrypt.php");
const TOKEN = 'zhichi';
const ENCODING_AES_KEY = 'VlYzNVFxdzdKVzNXMmVWT291QkIyODV4bEp2NUJvNTg';
const CLIENT_ID = 'test_c_id';



$timeStamp = time();
$nonce = "";
$str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
$max = strlen($str_pol) - 1;
for ($i = 0; $i < 8; $i++) {
    $nonce .= $str_pol[mt_rand(0, $max)];
}

$crypt = new JiSuCrypt(TOKEN, ENCODING_AES_KEY, CLIENT_ID);

//即速云加密
$msg = '"{"data":"OK"}"';
$errCode = $crypt->EncryptMsg($msg, $timeStamp, $nonce, $encryptMsg);
echo 'encryptMsg:'.$encryptMsg;
echo "\n";

//客户端解密
$encryptMsg = json_decode($encryptMsg,true);
$decryptMsg = '';
$errCode = $crypt->DecryptMsg($encryptMsg['signature'], $encryptMsg['timestamp'], $nonce, $encryptMsg['encrypt'],$decryptMsg);
echo 'decryptMsg:'.$decryptMsg;

