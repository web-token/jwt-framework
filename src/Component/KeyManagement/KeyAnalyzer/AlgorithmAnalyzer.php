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

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Jose\Component\Core\JWK;

final class AlgorithmAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag)
    {
        if (!$jwk->has('alg')) {
            $bag->add(Message::medium('The parameter "alg" should be added.'));
        }
    }
}
