<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use function extension_loaded;
use function in_array;
use InvalidArgumentException;
use function is_string;
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

    /**
     * @return non-empty-string
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        if (! $key->has('d')) {
            throw new InvalidArgumentException('The EC key is not private');
        }
        $d = $key->get('d');
        if (! is_string($d) || $d === '') {
            throw new InvalidArgumentException('Invalid "d" parameter.');
        }
        if (! $key->has('x')) {
            $x = sodium_crypto_sign_publickey_from_secretkey($d);
        } else {
            $x = $key->get('x');
        }
        if (! is_string($x) || $x === '') {
            throw new InvalidArgumentException('Invalid "x" parameter.');
        }
        /** @var non-empty-string $x */
        $x = Base64UrlSafe::decode($x);
        /** @var non-empty-string $d */
        $d = Base64UrlSafe::decode($d);
        $secret = $d . $x;

        return match ($key->get('crv')) {
            'Ed25519' => sodium_crypto_sign_detached($input, $secret),
            default => throw new InvalidArgumentException('Unsupported curve'),
        };
    }

    /**
     * @param non-empty-string $signature
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);
        $x = $key->get('x');
        if (! is_string($x)) {
            throw new InvalidArgumentException('Invalid "x" parameter.');
        }

        /** @var non-empty-string $public */
        $public = Base64UrlSafe::decode($x);

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
