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

namespace Jose\Component\Signature;

use Jose\Component\Checker\TokenTypeHeaderCheckerInterface;
use Jose\Component\Core\JWTInterface;

/**
 * Class JWSTokenHeaderChecker.
 */
final class JWSTokenHeaderChecker implements TokenTypeHeaderCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function supports(JWTInterface $jwt): bool
    {
        return $jwt instanceof JWS;
    }

    /**
     * {@inheritdoc}
     */
    public function retrieveTokenHeaders(JWTInterface $jwt, int $component, array &$protectedHeader, array &$unprotectedHeader): void
    {
        if (!$jwt instanceof JWS) {
            return;
        }

        if ($component > $jwt->countSignatures()) {
            throw new \InvalidArgumentException('Unknown signature index.');
        }
        $protectedHeader = $jwt->getSignature($component)->getProtectedHeaders();
        $unprotectedHeader = $jwt->getSignature($component)->getHeaders();
    }
}
