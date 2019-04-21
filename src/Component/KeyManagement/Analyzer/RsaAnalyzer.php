<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Analyzer;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

final class RsaAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ('RSA' !== $jwk->get('kty')) {
            return;
        }

        $this->checkExponent($jwk, $bag);
        $this->checkModulus($jwk, $bag);
    }

    private function checkExponent(JWK $jwk, MessageBag $bag): void
    {
        $exponent = unpack('l', str_pad(Base64Url::decode($jwk->get('e')), 4, "\0"))[1];
        if ($exponent < 65537) {
            $bag->add(Message::high('The exponent is too low. It should be at least 65537.'));
        }
    }

    private function checkModulus(JWK $jwk, MessageBag $bag): void
    {
        $n = 8 * mb_strlen(Base64Url::decode($jwk->get('n')), '8bit');
        if ($n < 2048) {
            $bag->add(Message::high('The key length is less than 2048 bits.'));
        }
        if ($jwk->has('d') && (!$jwk->has('p') || !$jwk->has('q') || !$jwk->has('dp') || !$jwk->has('dq') || !$jwk->has('p') || !$jwk->has('qi'))) {
            $bag->add(Message::medium('The key is a private RSA key, but Chinese Remainder Theorem primes are missing. These primes are not mandatory, but signatures and decryption processes are faster when available.'));
        }
    }

    private function checkOtherPrimes(JWK $jwk, MessageBag $bag): void
    {
        if (!$jwk->has('p') || !$jwk->has('q') || !$jwk->has('dp') || !$jwk->has('dq') || !$jwk->has('qi')) {
            $bag->add(Message::medium('Other primes are not set. The key can be optimized.'));
        }
    }
}
