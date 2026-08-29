<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\Wrapper as WrapperInterface;
use Jose\Component\Core\Exception\DecryptionFailedException;
use Jose\Component\Core\Exception\EncryptionFailedException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Override;
use function extension_loaded;
use function in_array;
use function is_string;
use function sprintf;
use const OPENSSL_RAW_DATA;

abstract readonly class AESGCMKW implements KeyWrapping
{
    public function __construct()
    {
        if (! extension_loaded('openssl')) {
            throw new MissingDependencyException('Please install the OpenSSL extension');
        }
        if (! interface_exists(WrapperInterface::class)) {
            throw new MissingDependencyException('Please install "spomky-labs/aes-key-wrap" to use AES-KW algorithms');
        }
    }

    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    /**
     * @param array<string, mixed> $completeHeader
     * @param array<string, mixed> $additionalHeader
     */
    #[Override]
    public function wrapKey(JWK $key, string $cek, array $completeHeader, array &$additionalHeader): string
    {
        $kek = $this->getKey($key);
        $iv = random_bytes(96 / 8);
        $additionalHeader['iv'] = Base64UrlSafe::encodeUnpadded($iv);

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $tag = '';
        $encrypted_cek = openssl_encrypt($cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if ($encrypted_cek === false) {
            throw new EncryptionFailedException('Unable to encrypt the CEK');
        }
        $additionalHeader['tag'] = Base64UrlSafe::encodeUnpadded($tag);

        return $encrypted_cek;
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    #[Override]
    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $kek = $this->getKey($key);
        (isset($completeHeader['iv']) && is_string($completeHeader['iv'])) || throw new InvalidHeaderParameterException(
            'Parameter "iv" is missing.'
        );
        (isset($completeHeader['tag']) && is_string($completeHeader['tag'])) || throw new InvalidHeaderParameterException(
            'Parameter "tag" is missing.'
        );

        $tag = Base64UrlSafe::decodeNoPadding($completeHeader['tag']);
        $iv = Base64UrlSafe::decodeNoPadding($completeHeader['iv']);

        $mode = sprintf('aes-%d-gcm', $this->getKeySize());
        $cek = openssl_decrypt($encrypted_cek, $mode, $kek, OPENSSL_RAW_DATA, $iv, $tag, '');
        if ($cek === false) {
            throw new DecryptionFailedException('Unable to decrypt the CEK');
        }

        return $cek;
    }

    #[Override]
    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    protected function getKey(JWK $key): string
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidKeyException('Wrong key type.');
        }
        if (! $key->has('k')) {
            throw new InvalidKeyException('The key parameter "k" is missing.');
        }
        $k = $key->get('k');
        if (! is_string($k)) {
            throw new InvalidKeyException('The key parameter "k" is invalid.');
        }

        return Base64UrlSafe::decodeNoPadding($k);
    }

    abstract protected function getKeySize(): int;
}
