<?php

declare(strict_types=1);

namespace Jose\Experimental\KeyEncryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryption;
use RuntimeException;
use function in_array;
use function is_string;
use const OPENSSL_RAW_DATA;

abstract class AESCTR implements KeyEncryption
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    public function encryptKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $k = $this->getKey($key);
        $iv = random_bytes(16);

        // We set header parameters
        $additionalHeader['iv'] = Base64UrlSafe::encodeUnpadded($iv);

        $result = openssl_encrypt($cek, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if ($result === false) {
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
        isset($header['iv']) || throw new InvalidArgumentException('The header parameter "iv" is missing.');
        is_string($header['iv']) || throw new InvalidArgumentException('The header parameter "iv" is not valid.');
        $iv = Base64UrlSafe::decodeNoPadding($header['iv']);

        $result = openssl_decrypt($encrypted_cek, $this->getMode(), $k, OPENSSL_RAW_DATA, $iv);
        if ($result === false) {
            throw new RuntimeException('Unable to decrypt the CEK');
        }

        return $result;
    }

    public function getKeyManagementMode(): string
    {
        return self::MODE_ENCRYPT;
    }

    abstract protected function getMode(): string;

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

        return Base64UrlSafe::decodeNoPadding($k);
    }
}
