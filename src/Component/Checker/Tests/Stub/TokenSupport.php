<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests\Stub;

use Jose\Component\Checker\TokenTypeSupportInterface;
use Jose\Component\Core\JWTInterface;

/**
 * Class TokenSupport.
 */
final class TokenSupport implements TokenTypeSupportInterface
{
    /**
     * {@inheritdoc}
     */
    public function retrieveTokenHeaders(JWTInterface $jwt, int $signature, array &$protectedHeader, array &$unprotectedHeader): void
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
    public function supports(JWTInterface $jwt): bool
    {
        return $jwt instanceof Token;
    }
}
