<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;
use function is_string;

final class RSA15 extends RSA
{
    /**
     * @var array<string, int>
     */
    private const CEK_LENGTHS = [
        'A128GCM' => 16,
        'A192GCM' => 24,
        'A256GCM' => 32,
        'A128CBC-HS256' => 32,
        'A192CBC-HS384' => 48,
        'A256CBC-HS512' => 64,
    ];

    public function name(): string
    {
        return 'RSA1_5';
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

        return RSACrypt::decrypt(
            $priv,
            $encrypted_cek,
            RSACrypt::ENCRYPTION_PKCS1,
            null,
            $this->getExpectedCekLength($header)
        );
    }

    protected function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_PKCS1;
    }

    protected function getHashAlgorithm(): ?string
    {
        return null;
    }

    /**
     * @param array<string, mixed> $header
     */
    private function getExpectedCekLength(array $header): ?int
    {
        $enc = $header['enc'] ?? null;
        if (! is_string($enc)) {
            return null;
        }

        return self::CEK_LENGTHS[$enc] ?? null;
    }
}
