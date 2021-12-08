<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker\Stub;

use InvalidArgumentException;
use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;

class TokenSupport implements TokenTypeSupport
{
    public function retrieveTokenHeaders(JWT $jwt, int $index, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (! $jwt instanceof Token) {
            throw new InvalidArgumentException('Unsupported token.');
        }
        $protectedHeader = $jwt->getProtectedHeader();
        $unprotectedHeader = $jwt->getUnprotectedHeader();
    }

    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof Token;
    }
}
