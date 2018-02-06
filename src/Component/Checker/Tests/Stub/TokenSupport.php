<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests\Stub;

use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;

/**
 * Class TokenSupport.
 */
class TokenSupport implements TokenTypeSupport
{
    /**
     * {@inheritdoc}
     */
    public function retrieveTokenHeaders(JWT $jwt, int $signature, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (!$jwt instanceof Token) {
            throw new \InvalidArgumentException('Unsupported token.');
        }

        $protectedHeader = $jwt->getProtectedHeader();
        $unprotectedHeader = $jwt->getUnprotectedHeader();
    }

    /**
     * {@inheritdoc}
     */
    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof Token;
    }
}
