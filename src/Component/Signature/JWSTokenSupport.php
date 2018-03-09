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

namespace Jose\Component\Signature;

use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;

final class JWSTokenSupport implements TokenTypeSupport
{
    /**
     * {@inheritdoc}
     */
    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof JWS;
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveTokenHeaders(JWT $jwt, int $index, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (!$jwt instanceof JWS) {
            return;
        }

        if ($index > $jwt->countSignatures()) {
            throw new \InvalidArgumentException('Unknown signature index.');
        }
        $protectedHeader = $jwt->getSignature($index)->getProtectedHeader();
        $unprotectedHeader = $jwt->getSignature($index)->getHeader();
    }
}
