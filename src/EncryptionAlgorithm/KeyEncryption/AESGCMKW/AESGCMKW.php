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

    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $kek = $this->getKey($key);
        $this->checkAdditionalParameters($completeHeader);

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

    protected function checkAdditionalParameters(array $header): void
    {
        foreach (['iv', 'tag'] as $k) {
            if (! isset($header[$k])) {
                throw new InvalidArgumentException(sprintf('Parameter "%s" is missing.', $k));
            }
        }
    }

    abstract protected function getKeySize(): int;
}
