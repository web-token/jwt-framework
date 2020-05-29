<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util;

use function chr;
use function count;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\Util\BigInteger;
use Jose\Component\Core\Util\Hash;
use Jose\Component\Core\Util\RSAKey;
use function ord;
use RuntimeException;

/**
 * @internal
 */
class RSACrypt
{
    /**
     * Optimal Asymmetric Encryption Padding (OAEP).
     */
    public const ENCRYPTION_OAEP = 1;

    /**
     * Use PKCS#1 padding.
     */
    public const ENCRYPTION_PKCS1 = 2;

    public static function encrypt(RSAKey $key, string $data, int $mode, ?string $hash = null): string
    {
        switch ($mode) {
            case self::ENCRYPTION_OAEP:
                return self::encryptWithRSAOAEP($key, $data, $hash);
            case self::ENCRYPTION_PKCS1:
                return self::encryptWithRSA15($key, $data);
            default:
                throw new InvalidArgumentException('Unsupported mode.');
        }
    }

    public static function decrypt(RSAKey $key, string $plaintext, int $mode, ?string $hash = null): string
    {
        switch ($mode) {
            case self::ENCRYPTION_OAEP:
                return self::decryptWithRSAOAEP($key, $plaintext, $hash);
            case self::ENCRYPTION_PKCS1:
                return self::decryptWithRSA15($key, $plaintext);
            default:
                throw new InvalidArgumentException('Unsupported mode.');
        }
    }

    public static function encryptWithRSA15(RSAKey $key, string $data): string
    {
        $mLen = mb_strlen($data, '8bit');
        if ($mLen > $key->getModulusLength() - 11) {
            throw new InvalidArgumentException('Message too long');
        }

        $psLen = $key->getModulusLength() - $mLen - 3;
        $ps = '';
        while (mb_strlen($ps, '8bit') !== $psLen) {
            $temp = random_bytes($psLen - mb_strlen($ps, '8bit'));
            $temp = str_replace("\x00", '', $temp);
            $ps .= $temp;
        }
        $type = 2;
        $data = chr(0).chr($type).$ps.chr(0).$data;

        $data = BigInteger::createFromBinaryString($data);
        $c = self::getRSAEP($key, $data);

        return self::convertIntegerToOctetString($c, $key->getModulusLength());
    }

    public static function decryptWithRSA15(RSAKey $key, string $c): string
    {
        if (mb_strlen($c, '8bit') !== $key->getModulusLength()) {
            throw new InvalidArgumentException('Unable to decrypt');
        }
        $c = BigInteger::createFromBinaryString($c);
        $m = self::getRSADP($key, $c);
        $em = self::convertIntegerToOctetString($m, $key->getModulusLength());
        if (0 !== ord($em[0]) || ord($em[1]) > 2) {
            throw new InvalidArgumentException('Unable to decrypt');
        }
        $ps = mb_substr($em, 2, (int) mb_strpos($em, chr(0), 2, '8bit') - 2, '8bit');
        $m = mb_substr($em, mb_strlen($ps, '8bit') + 3, null, '8bit');
        if (mb_strlen($ps, '8bit') < 8) {
            throw new InvalidArgumentException('Unable to decrypt');
        }

        return $m;
    }

    /**
     * Encryption.
     */
    public static function encryptWithRSAOAEP(RSAKey $key, string $plaintext, string $hash_algorithm): string
    {
        /** @var Hash $hash */
        $hash = Hash::$hash_algorithm();
        $length = $key->getModulusLength() - 2 * $hash->getLength() - 2;
        if (0 >= $length) {
            throw new RuntimeException();
        }
        $plaintext = mb_str_split($plaintext, $length, '8bit');
        if (!is_array($plaintext)) {
            throw new RuntimeException('Invalid payload');
        }
        $ciphertext = '';
        foreach ($plaintext as $m) {
            $ciphertext .= self::encryptRSAESOAEP($key, $m, $hash);
        }

        return $ciphertext;
    }

    /**
     * Decryption.
     */
    public static function decryptWithRSAOAEP(RSAKey $key, string $ciphertext, string $hash_algorithm): string
    {
        if (0 >= $key->getModulusLength()) {
            throw new RuntimeException('Invalid modulus length');
        }
        $hash = Hash::$hash_algorithm();
        $ciphertext = mb_str_split($ciphertext, $key->getModulusLength(), '8bit');
        if (!is_array($ciphertext)) {
            throw new RuntimeException('Invalid ciphertext');
        }
        $ciphertext[count($ciphertext) - 1] = str_pad($ciphertext[count($ciphertext) - 1], $key->getModulusLength(), chr(0), STR_PAD_LEFT);
        $plaintext = '';
        foreach ($ciphertext as $c) {
            $temp = self::getRSAESOAEP($key, $c, $hash);
            $plaintext .= $temp;
        }

        return $plaintext;
    }

    private static function convertIntegerToOctetString(BigInteger $x, int $xLen): string
    {
        $x = $x->toBytes();
        if (mb_strlen($x, '8bit') > $xLen) {
            throw new RuntimeException('Invalid length.');
        }

        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * Octet-String-to-Integer primitive.
     */
    private static function convertOctetStringToInteger(string $x): BigInteger
    {
        return BigInteger::createFromBinaryString($x);
    }

    /**
     * RSA EP.
     */
    private static function getRSAEP(RSAKey $key, BigInteger $m): BigInteger
    {
        if ($m->compare(BigInteger::createFromDecimal(0)) < 0 || $m->compare($key->getModulus()) > 0) {
            throw new RuntimeException();
        }

        return RSAKey::exponentiate($key, $m);
    }

    /**
     * RSA DP.
     */
    private static function getRSADP(RSAKey $key, BigInteger $c): BigInteger
    {
        if ($c->compare(BigInteger::createFromDecimal(0)) < 0 || $c->compare($key->getModulus()) > 0) {
            throw new RuntimeException();
        }

        return RSAKey::exponentiate($key, $c);
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
            $t .= $mgfHash->hash($mgfSeed.$c);
        }

        return mb_substr($t, 0, $maskLen, '8bit');
    }

    /**
     * RSAES-OAEP-ENCRYPT.
     */
    private static function encryptRSAESOAEP(RSAKey $key, string $m, Hash $hash): string
    {
        $mLen = mb_strlen($m, '8bit');
        $lHash = $hash->hash('');
        $ps = str_repeat(chr(0), $key->getModulusLength() - $mLen - 2 * $hash->getLength() - 2);
        $db = $lHash.$ps.chr(1).$m;
        $seed = random_bytes($hash->getLength());
        $dbMask = self::getMGF1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $maskedDB = (string) ($db ^ $dbMask);
        $seedMask = self::getMGF1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0).$maskedSeed.$maskedDB;

        $m = self::convertOctetStringToInteger($em);
        $c = self::getRSAEP($key, $m);

        return self::convertIntegerToOctetString($c, $key->getModulusLength());
    }

    /**
     * RSAES-OAEP-DECRYPT.
     */
    private static function getRSAESOAEP(RSAKey $key, string $c, Hash $hash): string
    {
        $c = self::convertOctetStringToInteger($c);
        $m = self::getRSADP($key, $c);
        $em = self::convertIntegerToOctetString($m, $key->getModulusLength());
        $lHash = $hash->hash('');
        $maskedSeed = mb_substr($em, 1, $hash->getLength(), '8bit');
        $maskedDB = mb_substr($em, $hash->getLength() + 1, null, '8bit');
        $seedMask = self::getMGF1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $seed = (string) ($maskedSeed ^ $seedMask);
        $dbMask = self::getMGF1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = mb_substr($db, 0, $hash->getLength(), '8bit');
        $m = mb_substr($db, $hash->getLength(), null, '8bit');
        if (!hash_equals($lHash, $lHash2)) {
            throw new RuntimeException();
        }
        $m = ltrim($m, chr(0));
        if (1 !== ord($m[0])) {
            throw new RuntimeException();
        }

        return mb_substr($m, 1, null, '8bit');
    }
}
