<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests\Stub;

use Assert\Assertion;
use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;

class TokenSupport implements TokenTypeSupport
{
    public function retrieveTokenHeaders(JWT $jwt, int $index, array &$protectedHeader, array &$unprotectedHeader): void
    {
        Assertion::isInstanceOf($jwt, Token::class, 'Unsupported token.');
        $protectedHeader = $jwt->getProtectedHeader();
        $unprotectedHeader = $jwt->getUnprotectedHeader();
    }

    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof Token;
    }
}
