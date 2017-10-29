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

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;
use ZxcvbnPhp\Zxcvbn;

/**
 * Class OctAnalyzer.
 */
final class OctAnalyzer implements JWKAnalyzerInterface
{
    /**
     * {@inheritdoc}
     */
    public function analyze(JWK $jwk, array &$messages)
    {
        if ('oct' !== $jwk->get('kty')) {
            return;
        }
        $k = Base64Url::decode($jwk->get('k'));
        $kLength = 8 * mb_strlen($k, '8bit');
        if ($kLength < 128) {
            $messages[] = 'The key length is less than 128 bits.';
        }

        if (class_exists(Zxcvbn::class)) {
            $zxcvbn = new Zxcvbn();
            $strength = $zxcvbn->passwordStrength($k);
            switch (true) {
                case $strength['score'] < 3:
                    $messages[] = 'The octet string is weak and easily guessable. Please change your key as soon as possible.';

                    break;
                case 3 === $strength['score']:
                    $messages[] = 'The octet string is safe, but a longer key is preferable.';

                    break;
                default:
                    break;
            }
        }
    }
}
