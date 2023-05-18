<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use function in_array;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\JWK;
use LogicException;
use const OPENSSL_RAW_DATA;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

final class Chacha20Poly1305 implements KeyEncryption
{
    public function __construct()
    {
        if (! in_array('chacha20-poly1305', openssl_get_cipher_methods(), true)) {
            throw new LogicException('The algorithm "chacha20-poly1305" is not supported in this platform.');
        }
    }

    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function name(): string
    {
        return 'chacha20-poly1305';
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $k = $this->getKey($key);
        $nonce = random_bytes(12);

        // We set header parameters
        $additionalHeader['nonce'] = Base64UrlSafe::encodeUnpadded($nonce);

        $tag = null;
        $result = openssl_encrypt($cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce, $tag);
        if ($result === false || ! is_string($tag)) {
            throw new RuntimeException('Unable to encrypt the CEK');
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $header
     */
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $k = $this->getKey($key);
        isset($header['nonce']) || throw new InvalidArgumentException('The header parameter "nonce" is missing.');
        is_string($header['nonce']) || throw new InvalidArgumentException('The header parameter "nonce" is not valid.');
        $nonce = Base64UrlSafe::decode($header['nonce']);
        if (mb_strlen($nonce, '8bit') !== 12) {
            throw new InvalidArgumentException('The header parameter "nonce" is not valid.');
        }

        $result = openssl_decrypt($encrypted_cek, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce);
        if ($result === false) {
            throw new RuntimeException('Unable to decrypt the CEK');
        }

        return $result;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    private function getKey(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        if (! $key->has('k')) {
            throw new InvalidArgumentException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidArgumentException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decode($k);
    }
}
