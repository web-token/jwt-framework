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

namespace Jose\Component\Encryption;

use Jose\Component\Checker\TokenTypeHeaderCheckerInterface;
use Jose\Component\Core\JWTInterface;

/**
 * Class JWETokenHeaderChecker.
 */
final class JWETokenHeaderChecker implements TokenTypeHeaderCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function supports(JWTInterface $jwt): bool
    {
        return $jwt instanceof JWE;
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveTokenHeaders(JWTInterface $jwt, int $component, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (!$jwt instanceof JWE) {
            return;
        }

        if ($component > $jwt->countRecipients()) {
            throw new \InvalidArgumentException('Unknown recipient index.');
        }
        $protectedHeader = $jwt->getSharedProtectedHeaders();
        $unprotectedHeader = $jwt->getSharedHeaders();
        $recipient = $jwt->getRecipient($component)->getHeaders();

        $unprotectedHeader = array_merge(
            $unprotectedHeader,
            $recipient
        );
    }
}
