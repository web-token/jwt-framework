<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Checker\Stub;

use InvalidArgumentException;
use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;

class TokenSupport implements TokenTypeSupport
{
    /**
     * @throws InvalidArgumentException if the token is not supported
     */
    public function retrieveTokenHeaders(JWT $jwt, int $index, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (!$jwt instanceof Token) {
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
