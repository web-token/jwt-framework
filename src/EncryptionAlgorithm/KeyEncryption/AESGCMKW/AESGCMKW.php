<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use function in_array;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\JWK;
use const OPENSSL_RAW_DATA;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

abstract class AESGCMKW implements KeyWrapping
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $kek = $this->getKey($key);
        $iv = random_bytes(96 / 8);
        $additionalHeader['iv'] = Base64UrlSafe::encodeUnpadded($iv);

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $tag = '';
        $encrypted_cek = openssl_encrypt($cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if ($encrypted_cek === false) {
            throw new RuntimeException('Unable to encrypt the CEK');
        }
        $additionalHeader['tag'] = Base64UrlSafe::encodeUnpadded($tag);

        return $encrypted_cek;
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $kek = $this->getKey($key);
        (isset($completeHeader['iv']) && is_string($completeHeader['iv'])) || throw new InvalidArgumentException(
            'Parameter "iv" is missing.'
        );
        (isset($completeHeader['tag']) && is_string($completeHeader['tag'])) || throw new InvalidArgumentException(
            'Parameter "tag" is missing.'
        );

        $tag = Base64UrlSafe::decode($completeHeader['tag']);
        $iv = Base64UrlSafe::decode($completeHeader['iv']);

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $cek = openssl_decrypt($encrypted_cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if ($cek === false) {
            throw new RuntimeException('Unable to decrypt the CEK');
        }

        return $cek;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    protected function getKey(JWK $key): string
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

    abstract protected function getKeySize(): int;
}
