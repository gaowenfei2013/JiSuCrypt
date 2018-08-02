<?php
include_once "sha1.php";
include_once "pkcs7Encoder.php";
include_once "errorCode.php";


class JiSuCrypt
{
	private $token;
	private $encodingAesKey;
	private $client_id;

	public function __construct($token, $encodingAesKey, $client_id)
	{
		$this->token = $token;
		$this->encodingAesKey = $encodingAesKey;
		$this->client_id = $client_id;
	}
	
    
	public function EncryptMsg($plain, $timeStamp, $nonce, &$encryptMsg)
	{
		$pc = new Prpcrypt($this->encodingAesKey);

		$array = $pc->encrypt($plain, $this->client_id);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}

		if ($timeStamp == null) {
			$timeStamp = time();
		}
		$encrypt = $array[1];

		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->token, $timeStamp, $nonce, $encrypt);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}
		$signature = $array[1];

		$encryptMsg = json_encode(array(
			"signature" => $signature,
			"encrypt" => $encrypt,
			"timestamp" => $timeStamp,
			"nonce" => $nonce
		));
		return ErrorCode::$OK;
	}


	public function DecryptMsg($signature, $timeStamp = null, $nonce, $encrypt, &$decryptMsg)
	{
		if (strlen($this->encodingAesKey) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt($this->encodingAesKey);

		if ($timeStamp == null) {
			$timeStamp = time();
		}

		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->token, $timeStamp, $nonce, $encrypt);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$verifySignature = $array[1];
		if ($verifySignature != $signature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($encrypt, $this->client_id);
		if ($result[0] != 0) {
			return $result[0];
		}
		$decryptMsg = $result[1];

		return ErrorCode::$OK;
	}

}

