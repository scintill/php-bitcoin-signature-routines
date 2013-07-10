<?php
// configure the ECC lib
if (!defined('USE_EXT')) {
	if (extension_loaded('gmp')) {
		define('USE_EXT', 'GMP');
	} else if(extension_loaded('bcmath')) {
		define('USE_EXT', 'BCMATH');
	} else {
		die('GMP or bcmath required. (GMP is faster).');
		// TODO I shouldn't be depending on bcmath for bcmath_Utils since GMP is faster...
	}
}
define('MAX_BASE', 256); // so we can use bcmath_Utils::bin2bc with "base256"

// curve definition
// http://www.secg.org/download/aid-784/sec2-v2.pdf
$secp256k1 = new CurveFp(
	'115792089237316195423570985008687907853269984665640564039457584007908834671663',
	'0', '7');
$secp256k1_G = new Point($secp256k1,
	'55066263022277343669578718895168534326250603453777594175500187360389116729240',
	'32670510020758816978083085130507043184471273380659243275938904335757337482424',
	'115792089237316195423570985008687907852837564279074904382605163141518161494337');

function isMessageSignatureValid($address, $signature, $message) {
	global $secp256k1_G;

	// extract parameters
	$address = base58check_decode($address);
	if (strlen($address) != 21 || $address[0] != "\x0") {
		throw new InvalidArgumentException('invalid Bitcoin address');
	}

	$signature = base64_decode($signature, true);
	if ($signature === false) {
		throw new InvalidArgumentException('invalid base64 signature');
	}

	if (strlen($signature) != 65) {
		throw new InvalidArgumentException('invalid signature length');
	}

	$recoveryFlags = ord($signature[0]) - 27;
	if ($recoveryFlags < 0 || $recoveryFlags > 7) {
		throw new InvalidArgumentException('invalid signature type');
	}
	$isCompressed = ($recoveryFlags & 4) != 0;

	// hash message, recover key
	$messageHash = hash('sha256', hash('sha256', "\x18Bitcoin Signed Message:\n" . numToVarIntString(strlen($message)).$message, true), true);
	$pubkey = recoverPubKey(bcmath_Utils::bin2bc(substr($signature, 1, 32)), bcmath_Utils::bin2bc(substr($signature, 33, 32)), $messageHash, $recoveryFlags, $secp256k1_G);
	if ($pubkey === false) {
		throw new InvalidArgumentException('unable to recover key');
	}
	$point = $pubkey->getPoint();

	// see that the key we recovered is for the address given
	if (!$isCompressed) {
		$pubBinStr = "\x04" . str_pad(bcmath_Utils::bc2bin($point->getX()), 32, "\x00", STR_PAD_LEFT) .
							  str_pad(bcmath_Utils::bc2bin($point->getY()), 32, "\x00", STR_PAD_LEFT);
	} else {
		$pubBinStr =	(isBignumEven($point->getY()) ? "\x02" : "\x03") .
							  str_pad(bcmath_Utils::bc2bin($point->getX()), 32, "\x00", STR_PAD_LEFT);
	}
	$derivedAddress = "\x00". hash('ripemd160', hash('sha256', $pubBinStr, true), true);

	return $address === $derivedAddress;
}

function isBignumEven($bnStr) {
	return (((int)$bnStr[strlen($bnStr)-1]) & 1) == 0;
}

// based on bitcoinjs-lib's implementation
// and SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public Key Recovery Operation".
// http://www.secg.org/download/aid-780/sec1-v2.pdf
function recoverPubKey($r, $s, $hash, $recoveryFlags, $G) {
	$isYEven = ($recoveryFlags & 1) != 0;
	$isSecondKey = ($recoveryFlags & 2) != 0;
	$curve = $G->getCurve();
	$signature = new Signature($r, $s);

	// Precalculate (p + 1) / 4 where p is the field order
	static $p_over_four; // XXX just assuming only one curve/prime will be used
	if (!$p_over_four) {
		if (USE_EXT == 'GMP') {
			$p_over_four = gmp_div(gmp_add($curve->getPrime(), 1), 4);
		} else if (USE_EXT == 'BCMATH') {
			$p_over_four = bcdiv(bcadd($curve->getPrime(), 1), 4);
		} else {
			throw new ErrorException("Please install BCMATH or GMP");
		}
	}

	// 1.1 Compute x
	if (!$isSecondKey) {
		$x = $r;
	} else {
		if (USE_EXT == 'GMP') {
			$x = gmp_add($r, $G->getOrder());
		} else if (USE_EXT == 'BCMATH') {
			$x = bcadd($r, $G->getOrder());
		} else {
			throw new ErrorException("Please install BCMATH or GMP");
		}
	}

	// 1.3 Convert x to point
	if (USE_EXT == 'GMP') {
		$alpha = gmp_mod(gmp_add(gmp_add(gmp_pow($x, 3), gmp_mul($curve->getA(), $x)), $curve->getB()), $curve->getPrime());
	} else if (USE_EXT == 'BCMATH') {
		$alpha = bcmod(bcadd(bcadd(bcpow($x, 3), bcmul($curve->getA(), $x)), $curve->getB()), $curve->getPrime());
	} else {
		throw new ErrorException("Please install BCMATH or GMP");
	}
	$beta = NumberTheory::modular_exp($alpha, $p_over_four, $curve->getPrime());

	// If beta is even, but y isn't or vice versa, then convert it,
	// otherwise we're done and y == beta.
	if (isBignumEven($beta) == $isYEven) {
		if (USE_EXT == 'GMP') {
			$y = gmp_sub($curve->getPrime(), $beta);
		} else if (USE_EXT == 'BCMATH') {
			$y = bcsub($curve->getPrime(), $beta);
		} else {
			throw new ErrorException("Please install BCMATH or GMP");
		}
	} else {
		$y = $beta;
	}

	// 1.4 Check that nR is at infinity (implicitly done in construtor)
	$R = new Point($curve, $x, $y, $G->getOrder());

	// 1.5 Compute e
	$e = bcmath_Utils::bin2bc($hash);

	$point_negate = function($p) { return new Point($p->curve, $p->x, bcsub(0, $p->y), $p->order); };

	// 1.6.1 Compute a candidate public key Q = r^-1 (sR - eG)
	$rInv = NumberTheory::inverse_mod($r, $G->getOrder());
	$eGNeg = $point_negate(Point::mul($e, $G));
	$Q = Point::mul($rInv, Point::add(Point::mul($s, $R), $eGNeg));

	// 1.6.2 Test Q as a public key
	$Qk = new PublicKey($G, $Q);
	if ($Qk->verifies($e, $signature)) {
		return $Qk;
	}

	return false;
}

function base58check_decode($str) {
	$v = bcmath_Utils::base2dec($str, 58, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
	$v = bcmath_Utils::bc2bin($v);
	// for each leading 1, pre-pad the byte array with a 0
	for ($i = 0; $i < strlen($str); $i++) {
		if ($str[$i] != '1') {
			break;
		}
		$v = "\x00" . $v;
	}

	$checksum = substr($v, -4);
	$v = substr($v, 0, -4);

	$expCheckSum = substr(hash('sha256', hash('sha256', $v, true), true), 0, 4);

	if ($expCheckSum != $checksum) {
		throw new InvalidArgumentException('invalid checksum');
	}

	return $v;
}

function numToVarIntString($i) {
	if ($i < 0xfd) {
		return chr($i);
	} else if ($i <= 0xffff) {
		return pack('Cv', 0xfd, $i);
	} else if ($i <= 0xffffffff) {
		return pack('CV', 0xfe, $i);
	} else {
		throw new InvalidArgumentException('int too large');
	}
}

// Setup-stuff cribbed from index.php in the ECC repo
function __autoload($f) {
	$base = "phpecc/";
	$interfaceFile = $base . "classes/interface/" . $f . "Interface.php";

	if (file_exists($interfaceFile)) {
		require_once $interfaceFile;
	}

	$classFile = $base . "classes/" . $f . ".php";
	if (file_exists($classFile)) {
		require_once $classFile;
	}

	$utilFile = $base . "classes/util/" . $f . ".php";
	if (file_exists($utilFile)) {
		require_once $utilFile;
	}
}

