<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use function chr;
use function count;
use function in_array;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\BigInteger;
use Jose\Component\Core\Util\Hash;
use Jose\Component\Core\Util\RSAKey;
use LogicException;
use function ord;
use RuntimeException;
use const STR_PAD_LEFT;

abstract class RSA implements KeyEncryption
{
    public function allowedKeyTypes(): array
    {
        return ['RSA'];
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $this->checkKey($key);
        $pub = RSAKey::toPublic(RSAKey::createFromJWK($key));

        return $this->encrypt($pub, $cek, $this->getHashAlgorithm());
    }

    /**
     * @param array<string, mixed> $header
     */
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $this->checkKey($key);
        if (! $key->has('d')) {
            throw new InvalidArgumentException('The key is not a private key');
        }
        $priv = RSAKey::createFromJWK($key);

        return $this->decrypt($priv, $encrypted_cek, $this->getHashAlgorithm());
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    protected function checkKey(JWK $key): void
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
    }

    abstract protected function getEncryptionMode(): int;

    abstract protected function getHashAlgorithm(): ?string;

    private function encrypt(RSAKey $key, string $data, string $hash): string
    {
        if ($hash === null) {
            throw new LogicException('Hash shall be defined for RSA OAEP cyphering');
        }

        return self::encryptWithRSAOAEP($key, $data, $hash);
    }

    private function decrypt(RSAKey $key, string $plaintext, string $hash): string
    {
        return self::decryptWithRSAOAEP($key, $plaintext, $hash);
    }

    /**
     * Encryption.
     */
    private function encryptWithRSAOAEP(RSAKey $key, string $plaintext, string $hash_algorithm): string
    {
        /** @var Hash $hash */
        $hash = Hash::$hash_algorithm();
        $length = $key->getModulusLength() - 2 * $hash->getLength() - 2;
        if ($length <= 0) {
            throw new RuntimeException();
        }
        $splitPlaintext = mb_str_split($plaintext, $length, '8bit');
        $ciphertext = '';
        foreach ($splitPlaintext as $m) {
            $ciphertext .= self::encryptRSAESOAEP($key, $m, $hash);
        }

        return $ciphertext;
    }

    /**
     * Decryption.
     */
    private function decryptWithRSAOAEP(RSAKey $key, string $ciphertext, string $hash_algorithm): string
    {
        if ($key->getModulusLength() <= 0) {
            throw new RuntimeException('Invalid modulus length');
        }
        $hash = Hash::$hash_algorithm();
        $splitCiphertext = mb_str_split($ciphertext, $key->getModulusLength(), '8bit');
        $splitCiphertext[count($splitCiphertext) - 1] = str_pad(
            $splitCiphertext[count($splitCiphertext) - 1],
            $key->getModulusLength(),
            chr(0),
            STR_PAD_LEFT
        );
        $plaintext = '';
        foreach ($splitCiphertext as $c) {
            $temp = self::getRSAESOAEP($key, $c, $hash);
            $plaintext .= $temp;
        }

        return $plaintext;
    }

    private function convertIntegerToOctetString(BigInteger $x, int $xLen): string
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
    private function convertOctetStringToInteger(string $x): BigInteger
    {
        return BigInteger::createFromBinaryString($x);
    }

    /**
     * RSA EP.
     */
    private function getRSAEP(RSAKey $key, BigInteger $m): BigInteger
    {
        if ($m->compare(BigInteger::createFromDecimal(0)) < 0 || $m->compare($key->getModulus()) > 0) {
            throw new RuntimeException();
        }

        return RSAKey::exponentiate($key, $m);
    }

    /**
     * RSA DP.
     */
    private function getRSADP(RSAKey $key, BigInteger $c): BigInteger
    {
        if ($c->compare(BigInteger::createFromDecimal(0)) < 0 || $c->compare($key->getModulus()) > 0) {
            throw new RuntimeException();
        }

        return RSAKey::exponentiate($key, $c);
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
     * RSAES-OAEP-ENCRYPT.
     */
    private function encryptRSAESOAEP(RSAKey $key, string $m, Hash $hash): string
    {
        $mLen = mb_strlen($m, '8bit');
        $lHash = $hash->hash('');
        $ps = str_repeat(chr(0), $key->getModulusLength() - $mLen - 2 * $hash->getLength() - 2);
        $db = $lHash . $ps . chr(1) . $m;
        $seed = random_bytes($hash->getLength());
        $dbMask = self::getMGF1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $maskedDB = $db ^ $dbMask;
        $seedMask = self::getMGF1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0) . $maskedSeed . $maskedDB;

        $m = self::convertOctetStringToInteger($em);
        $c = self::getRSAEP($key, $m);

        return self::convertIntegerToOctetString($c, $key->getModulusLength());
    }

    /**
     * RSAES-OAEP-DECRYPT.
     */
    private function getRSAESOAEP(RSAKey $key, string $c, Hash $hash): string
    {
        $c = self::convertOctetStringToInteger($c);
        $m = self::getRSADP($key, $c);
        $em = self::convertIntegerToOctetString($m, $key->getModulusLength());
        $lHash = $hash->hash('');
        $maskedSeed = mb_substr($em, 1, $hash->getLength(), '8bit');
        $maskedDB = mb_substr($em, $hash->getLength() + 1, null, '8bit');
        $seedMask = self::getMGF1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = self::getMGF1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = mb_substr($db, 0, $hash->getLength(), '8bit');
        $m = mb_substr($db, $hash->getLength(), null, '8bit');
        if (! hash_equals($lHash, $lHash2)) {
            throw new RuntimeException();
        }
        $m = ltrim($m, chr(0));
        if (ord($m[0]) !== 1) {
            throw new RuntimeException();
        }

        return mb_substr($m, 1, null, '8bit');
    }
}
