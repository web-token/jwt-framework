<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\BigInteger;
use Jose\Component\Core\Util\Hash;
use Jose\Component\Core\Util\RSAKey;
use RuntimeException;
use function chr;
use function extension_loaded;
use function in_array;
use function ord;
use const STR_PAD_LEFT;

abstract class RSAPSS implements SignatureAlgorithm
{
    public function __construct()
    {
        if (! extension_loaded('openssl')) {
            throw new RuntimeException('The OpenSSL extension must be loaded.');
        }
    }

    public function allowedKeyTypes(): array
    {
        return ['RSA'];
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);
        $pub = RSAKey::createFromJWK($key->toPublic());

        return $this->verifyWithPSS($pub, $input, $signature, $this->getAlgorithm());
    }

    /**
     * @return non-empty-string
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        if (! $key->has('d')) {
            throw new InvalidArgumentException('The key is not a private key.');
        }

        $priv = RSAKey::createFromJWK($key);

        return $this->computeSignature($priv, $input, $this->getAlgorithm());
    }

    abstract protected function getAlgorithm(): string;

    private function checkKey(JWK $key): void
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        foreach (['n', 'e'] as $k) {
            if (! $key->has($k)) {
                throw new InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
    }

    /**
     * @return non-empty-string
     */
    private function computeSignature(RSAKey $key, string $message, string $hash): string
    {
        $em = $this->encodeEMSAPSS($message, 8 * $key->getModulusLength() - 1, Hash::$hash());
        $message = BigInteger::createFromBinaryString($em);
        $signature = RSAKey::exponentiate($key, $message);
        $result = $this->convertIntegerToOctetString($signature, $key->getModulusLength());
        if ($result === '') {
            throw new InvalidArgumentException('Invalid signature.');
        }

        return $result;
    }

    /**
     * Verifies a signature.
     */
    private function verifyWithPSS(RSAKey $key, string $message, string $signature, string $hash): bool
    {
        if (mb_strlen($signature, '8bit') !== $key->getModulusLength()) {
            throw new RuntimeException();
        }
        $s2 = BigInteger::createFromBinaryString($signature);
        $m2 = RSAKey::exponentiate($key, $s2);
        $em = $this->convertIntegerToOctetString($m2, $key->getModulusLength());
        $modBits = 8 * $key->getModulusLength() - 1;
        $hashingFunction = Hash::$hash();

        return $this->verifyEMSAPSS($message, $em, $modBits, $hashingFunction);
    }

    private function convertIntegerToOctetString(BigInteger $x, int $xLen): string
    {
        $x = $x->toBytes();
        if (mb_strlen($x, '8bit') > $xLen) {
            throw new RuntimeException();
        }

        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * MGF1.
     */
    private function getMGF1(string $mgfSeed, int $maskLen, Hash $mgfHash): string
    {
        $t = '';
        $count = ceil($maskLen / $mgfHash->getLength());
        for ($i = 0; $i < $count; ++$i) {
            $c = pack('N', $i);
            $t .= $mgfHash->hash($mgfSeed . $c);
        }

        return mb_substr($t, 0, $maskLen, '8bit');
    }

    /**
     * EMSA-PSS-ENCODE.
     */
    private function encodeEMSAPSS(string $message, int $modulusLength, Hash $hash): string
    {
        $emLen = ($modulusLength + 1) >> 3;
        $sLen = $hash->getLength();
        $mHash = $hash->hash($message);
        if ($emLen <= $hash->getLength() + $sLen + 2) {
            throw new RuntimeException();
        }
        $salt = random_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h = $hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $hash->getLength() - 2);
        $db = $ps . chr(1) . $salt;
        $dbMask = $this->getMGF1($h, $emLen - $hash->getLength() - 1, $hash);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($modulusLength & 7)) & $maskedDB[0];

        return $maskedDB . $h . chr(0xBC);
    }

    /**
     * EMSA-PSS-VERIFY.
     */
    private function verifyEMSAPSS(string $message, string $em, int $modBits, Hash $hash): bool
    {
        $emLen = ($modBits + 1) >> 3;
        $sLen = $hash->getLength();
        $mHash = $hash->hash($message);
        if ($emLen < $hash->getLength() + $sLen + 2) {
            throw new InvalidArgumentException();
        }
        if ($em[mb_strlen($em, '8bit') - 1] !== chr(0xBC)) {
            throw new InvalidArgumentException();
        }
        $maskedDB = mb_substr($em, 0, -$hash->getLength() - 1, '8bit');
        $h = mb_substr($em, -$hash->getLength() - 1, $hash->getLength(), '8bit');
        $temp = chr(0xFF << ($modBits & 7));
        if ((~$maskedDB[0] & $temp) !== $temp) {
            throw new InvalidArgumentException();
        }
        $dbMask = $this->getMGF1($h, $emLen - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($modBits & 7)) & $db[0];
        $temp = $emLen - $hash->getLength() - $sLen - 2;
        if (mb_substr($db, 0, $temp, '8bit') !== str_repeat(chr(0), $temp)) {
            throw new InvalidArgumentException();
        }
        if (ord($db[$temp]) !== 1) {
            throw new InvalidArgumentException();
        }
        $salt = mb_substr($db, $temp + 1, null, '8bit'); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
        $h2 = $hash->hash($m2);

        return hash_equals($h, $h2);
    }
}
