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

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Jose\Component\Core\JWK;

/**
 * Class NoneAnalyzer.
 */
final class NoneAnalyzer implements JWKAnalyzer
{
    /**
     * {@inheritdoc}
     */
    public function analyze(JWK $jwk, array &$messages)
    {
        if ('none' !== $jwk->get('kty')) {
            return;
        }
        $messages[] = 'This key is a meant to be used with the algorithm "none". This algorithm is not secured and should be used with care.';
    }
}
