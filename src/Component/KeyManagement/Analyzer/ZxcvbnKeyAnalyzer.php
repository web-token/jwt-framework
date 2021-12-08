<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ZxcvbnPhp\Zxcvbn;

final class ZxcvbnKeyAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ('oct' !== $jwk->get('kty')) {
            return;
        }
        $k = Base64UrlSafe::decode($jwk->get('k'));
        if (class_exists(Zxcvbn::class)) {
            $zxcvbn = new Zxcvbn();
            $strength = $zxcvbn->passwordStrength($k);

            switch (true) {
                case $strength['score'] < 3:
                    $bag->add(Message::high('The octet string is weak and easily guessable. Please change your key as soon as possible.'));

                    break;

                case 3 === $strength['score']:
                    $bag->add(Message::medium('The octet string is safe, but a longer key is preferable.'));

                    break;

                default:
                    break;
            }
        }
    }
}
