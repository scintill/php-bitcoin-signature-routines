# php-bitcoin-signature-routines

PHP routines for verifying Bitcoin signatures.  Requires PHP 5.3.2 and the extension GMP 4.2.0 or better. GMP may be available in a package called "php5-gmp" or similar for your system.

The main code is in verifymessage.php, with tests in test/verifymessage.php.  You will probably want to encapsulate the code more nicely, but since the ECC library needs to be configured specially and I am not up-to-date on the latest PHP packaging hotness anyway, I figured it would be best to leave that up to users to do how they like best.