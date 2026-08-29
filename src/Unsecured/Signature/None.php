<?php

declare(strict_types=1);

namespace Jose\Unsecured\Signature;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Override;
use function in_array;

/**
 * The "none" algorithm of RFC 7515, used by unsecured JWS.
 *
 * This algorithm does not sign anything and verifies nothing: a JWS using it offers no integrity protection at all.
 * It is only shipped for the applications that have to interoperate with unsecured JWT (RFC 7519, section 6).
 *
 * The class is not final because the deprecated Jose\Component\Signature\Algorithm\None extends it until 5.0.0.
 */
readonly class None implements SignatureAlgorithm
{
    #[Override]
    public function allowedKeyTypes(): array
    {
        return ['none'];
    }

    #[Override]
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);

        return '';
    }

    #[Override]
    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        return $signature === '';
    }

    #[Override]
    public function name(): string
    {
        return 'none';
    }

    private function checkKey(JWK $key): void
    {
        if (! in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new InvalidKeyException('Wrong key type.');
        }
    }
}
