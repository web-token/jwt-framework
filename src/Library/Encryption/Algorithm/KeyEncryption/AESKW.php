<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use AESKW\A128KW as A128KWWrapper;
use AESKW\A192KW as A192KWWrapper;
use AESKW\A256KW as A256KWWrapper;
use AESKW\Wrapper as WrapperInterface;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\MissingDependencyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\AESKeyWrap;
use Override;
use function in_array;
use function is_string;
use function strlen;
use function trigger_deprecation;

abstract readonly class AESKW implements KeyWrapping
{
    public function __construct()
    {
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
        $k = $this->getKey($key);
        $wrapper = $this->getWrapper();
        $this->deprecateLongerKey(strlen($k) * 8);

        return $wrapper::wrap($k, $cek);
    }

    /**
     * @param array<string, mixed> $completeHeader
     */
    #[Override]
    public function unwrapKey(JWK $key, string $encrypted_cek, array $completeHeader): string
    {
        $k = $this->getKey($key);
        $wrapper = $this->getWrapper();
        $cek = AESKeyWrap::unwrap($wrapper, $k, $encrypted_cek);
        $this->deprecateLongerKey(strlen($k) * 8);

        return $cek;
    }

    #[Override]
    public function getKeyManagementMode(): string
    {
        return self::MODE_WRAP;
    }

    abstract protected function getWrapper(): WrapperInterface;

    private function getKey(JWK $key): string
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
        $k = Base64UrlSafe::decodeNoPadding($k);
        $keySize = $this->getKeySize();
        if ($keySize !== null && strlen($k) * 8 < $keySize) {
            throw new InvalidKeyException('Invalid key length.');
        }

        return $k;
    }

    private function getKeySize(): ?int
    {
        $wrapper = $this->getWrapper();

        return match (true) {
            $wrapper instanceof A128KWWrapper => 128,
            $wrapper instanceof A192KWWrapper => 192,
            $wrapper instanceof A256KWWrapper => 256,
            default => null,
        };
    }

    /**
     * Only called with a key that protects the CEK, so that the other keys of a key set tried on a token are not reported.
     */
    private function deprecateLongerKey(int $keyLength): void
    {
        $keySize = $this->getKeySize();
        if ($keySize === null || $keyLength <= $keySize) {
            return;
        }
        trigger_deprecation(
            'web-token/jwt-library',
            '4.3.0',
            'Using a key of %d bits with "%s" is deprecated and will not be possible in 5.0.0: the key must have exactly %d bits.',
            $keyLength,
            $this->name(),
            $keySize
        );
    }
}
