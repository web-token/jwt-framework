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

namespace Jose\Component\Encryption;

use Jose\Component\Checker\TokenTypeSupport;
use Jose\Component\Core\JWT;

/**
 * Class JWETokenSupport.
 */
final class JWETokenSupport implements TokenTypeSupport
{
    /**
     * {@inheritdoc}
     */
    public function supports(JWT $jwt): bool
    {
        return $jwt instanceof JWE;
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveTokenHeaders(JWT $jwt, int $component, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (!$jwt instanceof JWE) {
            return;
        }

        if ($component > $jwt->countRecipients()) {
            throw new \InvalidArgumentException('Unknown recipient index.');
        }
        $protectedHeader = $jwt->getSharedProtectedHeader();
        $unprotectedHeader = $jwt->getSharedHeader();
        $recipient = $jwt->getRecipient($component)->getHeader();

        $unprotectedHeader = array_merge(
            $unprotectedHeader,
            $recipient
        );
    }
}
