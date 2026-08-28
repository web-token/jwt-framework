<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\HMAC\Stub;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HMAC;
use Override;

/**
 * An algorithm that alters the signature by overriding hash(), the only way to do so before 4.3.0 introduced sign().
 */
final readonly class LegacyTruncatedHMAC extends HMAC
{
    #[Override]
    public function hash(JWK $key, string $input): string
    {
        return substr(parent::hash($key, $input), 0, 8);
    }

    #[Override]
    public function name(): string
    {
        return 'LEGACY-HS256/64';
    }

    #[Override]
    protected function getHashAlgorithm(): string
    {
        return 'sha256';
    }
}
