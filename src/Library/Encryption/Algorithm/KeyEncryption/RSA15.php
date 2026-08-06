<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\RSACrypt;
use Override;
use function func_get_arg;
use function func_num_args;
use function is_int;
use function is_string;
use function trigger_deprecation;

final readonly class RSA15 extends RSA
{
    /**
     * BC NOTE: deprecated since 4.2 and will be removed in 5.0. The expected CEK size is now provided by the
     * caller as the fourth argument of the "decryptKey" method.
     *
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

    #[Override]
    public function name(): string
    {
        return 'RSA1_5';
    }

    /**
     * The size (in bits) of the key expected by the content encryption algorithm may be passed as a fourth
     * argument. That argument is not declared yet for BC reasons; it will be in 5.0 (see the KeyEncryption
     * interface).
     *
     * @param array<string, mixed> $header
     */
    #[Override]
    public function decryptKey(JWK $key, string $encrypted_cek, array $header): string
    {
        $encryptionKeyLength = func_num_args() > 3 ? func_get_arg(3) : null;
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
            $this->getExpectedCekLength($header, $encryptionKeyLength)
        );
    }

    #[Override]
    protected function getEncryptionMode(): int
    {
        return RSACrypt::ENCRYPTION_PKCS1;
    }

    #[Override]
    protected function getHashAlgorithm(): ?string
    {
        return null;
    }

    /**
     * Returns the expected CEK length in bytes.
     *
     * @param array<string, mixed> $header
     * @param mixed $encryptionKeyLength Size (in bits) of the key expected by the content encryption
     *                                   algorithm, or null when the caller did not provide it
     */
    private function getExpectedCekLength(array $header, mixed $encryptionKeyLength): ?int
    {
        if (is_int($encryptionKeyLength)) {
            return intdiv($encryptionKeyLength, 8);
        }

        trigger_deprecation(
            'web-token/jwt-framework',
            '4.2.0',
            'Calling "%s::decryptKey()" without the size of the key expected by the content encryption algorithm as fourth argument is deprecated. That size is currently deduced from a hardcoded table that will be removed in 5.0.0: pass the value returned by "getCEKSize()" of the content encryption algorithm in use instead.',
            self::class
        );

        $enc = $header['enc'] ?? null;
        if (! is_string($enc)) {
            return null;
        }

        return self::CEK_LENGTHS[$enc] ?? null;
    }
}
