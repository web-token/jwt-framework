<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker\Stub;

use InvalidArgumentException;
use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;
use Override;

final readonly class TokenSupport implements TokenTypeSupport
{
    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $unprotectedHeader
     */
    #[Override]
    public function retrieveTokenHeaders(JWT $jwt, int $index, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (! $jwt instanceof Token) {
            throw new InvalidArgumentException('Unsupported token.');
        }
        $protectedHeader = $jwt->getProtectedHeader();
        $unprotectedHeader = $jwt->getUnprotectedHeader();
    }

    #[Override]
    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof Token;
    }
}
