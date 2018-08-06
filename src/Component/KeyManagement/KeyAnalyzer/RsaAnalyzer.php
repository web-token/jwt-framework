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

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

final class RsaAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag)
    {
        if ('RSA' !== $jwk->get('kty')) {
            return;
        }
        $n = 8 * \mb_strlen(Base64Url::decode($jwk->get('n')), '8bit');
        if ($n < 2048) {
            $bag->add(Message::high('The key length is less than 2048 bits.'));
        }
        if ($jwk->has('d') && (!$jwk->has('p') || !$jwk->has('q') || !$jwk->has('dp') || !$jwk->has('dq') || !$jwk->has('p') || !$jwk->has('qi'))) {
            $bag->add(Message::medium('The key is a private RSA key, but Chinese Remainder Theorem primes are missing. These primes are not mandatory, but signatures and decryption processes are faster when available.'));
        }
    }
}
