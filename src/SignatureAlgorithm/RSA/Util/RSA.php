<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm\Util;

use function chr;
use InvalidArgumentException;
use Jose\Component\Core\Util\BigInteger;
use Jose\Component\Core\Util\Hash;
use Jose\Component\Core\Util\RSAKey;
use function ord;
use RuntimeException;
use const STR_PAD_LEFT;

/**
 * @internal
 */
final class RSA
{
    /**
     * Probabilistic Signature Scheme.
     */
    public const SIGNATURE_PSS = 1;

    /**
     * Use the PKCS#1.
     */
    public const SIGNATURE_PKCS1 = 2;

    /**
     * @return non-empty-string
     */
    public static function sign(RSAKey $key, string $message, string $hash, int $mode): string
    {
        switch ($mode) {
            case self::SIGNATURE_PSS:
                return self::signWithPSS($key, $message, $hash);

            case self::SIGNATURE_PKCS1:
                $result = openssl_sign($message, $signature, $key->toPEM(), $hash);
                if ($result !== true) {
                    throw new RuntimeException('Unable to sign the data');
                }

                return $signature;

            default:
                throw new InvalidArgumentException('Unsupported mode.');
        }
    }

    /**
     * Create a signature.
     *
     * @return non-empty-string
     */
    public static function signWithPSS(RSAKey $key, string $message, string $hash): string
    {
        $em = self::encodeEMSAPSS($message, 8 * $key->getModulusLength() - 1, Hash::$hash());
        $message = BigInteger::createFromBinaryString($em);
        $signature = RSAKey::exponentiate($key, $message);
        $result = self::convertIntegerToOctetString($signature, $key->getModulusLength());
        if ($result === '') {
            throw new InvalidArgumentException('Invalid signature.');
        }

        return $result;
    }

    public static function verify(RSAKey $key, string $message, string $signature, string $hash, int $mode): bool
    {
        return match ($mode) {
            self::SIGNATURE_PSS => self::verifyWithPSS($key, $message, $signature, $hash),
            self::SIGNATURE_PKCS1 => openssl_verify($message, $signature, $key->toPEM(), $hash) === 1,
            default => throw new InvalidArgumentException('Unsupported mode.'),
        };
    }

    /**
     * Verifies a signature.
     */
    public static function verifyWithPSS(RSAKey $key, string $message, string $signature, string $hash): bool
    {
        if (mb_strlen($signature, '8bit') !== $key->getModulusLength()) {
            throw new RuntimeException();
        }
        $s2 = BigInteger::createFromBinaryString($signature);
        $m2 = RSAKey::exponentiate($key, $s2);
        $em = self::convertIntegerToOctetString($m2, $key->getModulusLength());
        $modBits = 8 * $key->getModulusLength();

        return self::verifyEMSAPSS($message, $em, $modBits - 1, Hash::$hash());
    }

    private static function convertIntegerToOctetString(BigInteger $x, int $xLen): string
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
    private static function getMGF1(string $mgfSeed, int $maskLen, Hash $mgfHash): string
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
    private static function encodeEMSAPSS(string $message, int $modulusLength, Hash $hash): string
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
        $dbMask = self::getMGF1($h, $emLen - $hash->getLength() - 1, $hash);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($modulusLength & 7)) & $maskedDB[0];

        return $maskedDB . $h . chr(0xBC);
    }

    /**
     * EMSA-PSS-VERIFY.
     */
    private static function verifyEMSAPSS(string $m, string $em, int $emBits, Hash $hash): bool
    {
        $emLen = ($emBits + 1) >> 3;
        $sLen = $hash->getLength();
        $mHash = $hash->hash($m);
        if ($emLen < $hash->getLength() + $sLen + 2) {
            throw new InvalidArgumentException();
        }
        if ($em[mb_strlen($em, '8bit') - 1] !== chr(0xBC)) {
            throw new InvalidArgumentException();
        }
        $maskedDB = mb_substr($em, 0, -$hash->getLength() - 1, '8bit');
        $h = mb_substr($em, -$hash->getLength() - 1, $hash->getLength(), '8bit');
        $temp = chr(0xFF << ($emBits & 7));
        if ((~$maskedDB[0] & $temp) !== $temp) {
            throw new InvalidArgumentException();
        }
        $dbMask = self::getMGF1($h, $emLen - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
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
