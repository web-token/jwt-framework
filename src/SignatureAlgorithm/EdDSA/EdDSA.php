<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use function extension_loaded;
use function in_array;
use InvalidArgumentException;
use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

final class EdDSA implements SignatureAlgorithm
{
    public function __construct()
    {
        if (! extension_loaded('sodium')) {
            throw new RuntimeException('The extension "sodium" is not available. Please install it to use this method');
        }
    }

    public function allowedKeyTypes(): array
    {
        return ['OKP'];
    }

    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        if (! $key->has('d')) {
            throw new InvalidArgumentException('The EC key is not private');
        }
        $x = Base64UrlSafe::decode($key->get('x'));
        $d = Base64UrlSafe::decode($key->get('d'));
        $secret = $d . $x;

        return match ($key->get('crv')) {
            'Ed25519' => sodium_crypto_sign_detached($input, $secret),
            default => throw new InvalidArgumentException('Unsupported curve'),
        };
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        $public = Base64UrlSafe::decode($key->get('x'));

        return match ($key->get('crv')) {
            'Ed25519' => sodium_crypto_sign_verify_detached($signature, $input, $public),
            default => throw new InvalidArgumentException('Unsupported curve'),
        };
    }

    public function name(): string
    {
        return 'EdDSA';
    }

    private function checkKey(JWK $key): void
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidArgumentException('Wrong key type.');
        }
        foreach (['x', 'crv'] as $k) {
            if (! $key->has($k)) {
                throw new InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
        if ($key->get('crv') !== 'Ed25519') {
            throw new InvalidArgumentException('Unsupported curve.');
        }
    }
}
