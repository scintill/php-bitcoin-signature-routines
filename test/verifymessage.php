<?php
require_once(__DIR__ . '/../verifymessage.php');

// valid + recovery factor 0x20 + odd Y compressed
function test1() {
	return isMessageSignatureValid('17u1mDkgNcdwi44braeTKpvnfNnTrgvBfB', 'IJ6oyHmcmx9UDavYWgl33UPUwYMtuDAClggh+F2isIMyrqIuRIIOX1pn5z44j802STKBjPKbXac3eJmtgdKp4Go=', 'test signature');
}

// valid (another random k for the signature)
function test2() {
	return isMessageSignatureValid('17u1mDkgNcdwi44braeTKpvnfNnTrgvBfB', 'IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tg=', 'test signature');
}

// valid (uncompressed, empty message) + recovery factor 0x1b
function test3() {
	return isMessageSignatureValid('1HNPhhfsVTZ6Visozkzwi1NAk3yDQnmfgH', 'G7Q5ULHgIJhvORjhmF2wEFJloc3UzzCn4ypBPE+g9GOmz93t0WuLUzYSzAGpzN24qhK+uw4X1+7KtDH8WLLSdo8=', '');
}

// incorrect/modified message
function test4() {
	return !isMessageSignatureValid('17u1mDkgNcdwi44braeTKpvnfNnTrgvBfB', 'IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tg=', 'test evil attacker');
}

// incorrect/modified address
function test5() {
	return !isMessageSignatureValid('17qnunSja9HUsb6yAg7XG3sQeEABLSBA2w', 'IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tg=', 'test signature');
}

// mistyped address (checksum error)
function test6() {
	try {
		isMessageSignatureValid('17u1mDkgNcDwi44braeTKpvnfNnTrgvBfB', 'IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tg=', 'test signature');
	} catch (InvalidArgumentException $e) {
		if ($e->getMessage() == 'invalid checksum') {
			return true;
		}
	}

	return false;
}

// wrong type of address
function test7() {
	try {
		isMessageSignatureValid('38XoqKwB83brxkoQHmn7ggELnkSttNNnQq', 'IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tg=', 'test signature');
	} catch (InvalidArgumentException $e) {
		if ($e->getMessage() == 'invalid Bitcoin address') {
			return true;
		}
	}

	return false;
}

// malformed base64
function test8() {
	try {
		isMessageSignatureValid('17u1mDkgNcdwi44braeTKpvnfNnTrgvBfB', "I\x3fvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0T", 'test signature');
	} catch (InvalidArgumentException $e) {
		if ($e->getMessage() == 'invalid base64 signature') {
			return true;
		}
	}

	return false;
}

// malformed signature
function test9() {
	try {
		isMessageSignatureValid('17u1mDkgNcdwi44braeTKpvnfNnTrgvBfB', 'IHfvfadyMsn/P0tKH6UnDnbYiZcOWWhk8xbGIWUOwTX75MR8LfEn9Mdxq5R2h1IRXKaFxbqR6SfC3sZrHBdA0Tgg', 'test signature');
	} catch (InvalidArgumentException $e) {
		if ($e->getMessage() == 'invalid signature length') {
			return true;
		}
	}

	return false;
}

// recovery factor 0x1c
function test10() {
	return isMessageSignatureValid('1MhMaPFd9tDsg48597SWw28ZvcWfAjAyVk', 'HNt81qTEq+ufPZbpP15RmdyQ2+jqtMnSA7nAelevqtsMAO+aEyVOAqGB+MUlSmcRQaVPWuDzW6WtaN8nMM5stBQ=', 'test');
}

// TODO recovery factor 0x1d
// TODO recovery factor 0x1e

// recovery factor 0x1f + even Y compressed
function test11() {
	return isMessageSignatureValid('1C9CRMGBYrGKKQ6eEpwm4dzMqkRZxPB5xa', 'Hwt3ycjmA6LCbcTiFcj7o6odqX5PKeYPmL+dwcblLc/Xor1E2szTlEZKtHdzSrSz78PbYQUlX5a5VuDeSJLrEr0=', 'test');
}

// TODO recovery factor 0x21
// TODO recovery factor 0x22

// incorrect recovery factory, otherwise valid
function test12() {
	try {
		isMessageSignatureValid('1C9CRMGBYrGKKQ6eEpwm4dzMqkRZxPB5xa', 'IQt3ycjmA6LCbcTiFcj7o6odqX5PKeYPmL+dwcblLc/Xor1E2szTlEZKtHdzSrSz78PbYQUlX5a5VuDeSJLrEr0=', 'test');
	} catch (InvalidArgumentException $e) {
		if ($e->getMessage() == 'unable to recover key') {
			return true;
		}
	}

	return false;
}

// strlen == 0x100 (varint > 0xfd)
function test13() {
	return isMessageSignatureValid('1MhMaPFd9tDsg48597SWw28ZvcWfAjAyVk', 'G9ZsSEsKRUYfG2dXiLXyqgPPvxvX4xcHsSiAYAUG+TbgrYY5isGUHCTptWv5y7mqjjS89Xul+pzOtZcbO59J9n4=', str_repeat('A', 0x100));
}

// strlen == 0x10000 (varint > 0xffff)
function test14() {
	return isMessageSignatureValid('1MhMaPFd9tDsg48597SWw28ZvcWfAjAyVk', 'G/aO5gtIFN6bboNAfyYA9t/LDmFwG83YrWwfXjEGqMooBNUzi28BjvEeFf5nj87d4J5slTc2yHI2Sry+metEq6c=', str_repeat('A', 0x10000));
}

runTests(14);

function runTests($n) {
	for ($i = 1; $i <= $n; $i++) {
		try {
			if (call_user_func('test'.$i) === true) {
				echo "Test #$i passed\n";
			} else {
				echo "Test #$i FAILED!\n";
			}
		} catch (Exception $e) {
			echo "==> Got exception from test #$i: ".get_class($e).': '.$e->getMessage()."\n";
		}
	}
}
