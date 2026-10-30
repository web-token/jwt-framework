<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption\Util\HPKE;

use Jose\Component\Core\Exception\DecryptionFailedException;
use Jose\Component\Core\Exception\EncryptionFailedException;
use Jose\Component\Core\Exception\InvalidArgumentException;
use function in_array;
use function is_string;
use function sprintf;
use function strlen;
use function substr;
use const OPENSSL_RAW_DATA;

/**
 * The AEAD encryption algorithms of HPKE (draft-ietf-hpke-hpke section 7.3), all run by OpenSSL. The ciphertext is
 * the encrypted plaintext followed by the 16-byte authentication tag, Nt.
 *
 * AES-GCM is available wherever ext-openssl is. ChaCha20Poly1305 needs an OpenSSL library that provides the cipher,
 * as the experimental "chacha20-poly1305" key encryption algorithm does; isSupported() tells.
 *
 * @internal
 */
final readonly class AEAD
{
    private const TAG_LENGTH = 16;

    /**
     * @param int $id The AEAD identifier of the HPKE registry
     * @param string $cipher The cipher, as known by openssl_encrypt()
     * @param int $keyLength The key size in bytes, Nk
     * @param int $nonceLength The nonce size in bytes, Nn
     */
    private function __construct(
        public int $id,
        private string $cipher,
        public int $keyLength,
        public int $nonceLength
    ) {
    }

    public static function fromIdentifier(int $id): self
    {
        return match ($id) {
            0x0001 => self::aes128Gcm(),
            0x0002 => self::aes256Gcm(),
            0x0003 => self::chaCha20Poly1305(),
            default => throw new InvalidArgumentException(sprintf('Unsupported HPKE AEAD 0x%04x.', $id)),
        };
    }

    public static function aes128Gcm(): self
    {
        return new self(0x0001, 'aes-128-gcm', 16, 12);
    }

    public static function aes256Gcm(): self
    {
        return new self(0x0002, 'aes-256-gcm', 32, 12);
    }

    public static function chaCha20Poly1305(): self
    {
        return new self(0x0003, 'chacha20-poly1305', 32, 12);
    }

    public function isSupported(): bool
    {
        return in_array($this->cipher, openssl_get_cipher_methods(), true);
    }

    public function seal(string $key, string $nonce, string $aad, string $plaintext): string
    {
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            $this->cipher,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            self::TAG_LENGTH
        );
        if ($ciphertext === false || ! is_string($tag) || strlen($tag) !== self::TAG_LENGTH) {
            throw new EncryptionFailedException('Unable to encrypt the HPKE plaintext.');
        }

        return $ciphertext . $tag;
    }

    public function open(string $key, string $nonce, string $aad, string $ciphertext): string
    {
        if (strlen($ciphertext) < self::TAG_LENGTH) {
            throw new DecryptionFailedException('Unable to decrypt the HPKE ciphertext.');
        }
        $plaintext = openssl_decrypt(
            substr($ciphertext, 0, -self::TAG_LENGTH),
            $this->cipher,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            substr($ciphertext, -self::TAG_LENGTH),
            $aad
        );
        if ($plaintext === false) {
            throw new DecryptionFailedException('Unable to decrypt the HPKE ciphertext.');
        }

        return $plaintext;
    }
}
