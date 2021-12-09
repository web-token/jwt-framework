<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;

final class OctAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'oct') {
            return;
        }
        $k = Base64UrlSafe::decode($jwk->get('k'));
        $kLength = 8 * mb_strlen($k, '8bit');
        if ($kLength < 128) {
            $bag->add(Message::high('The key length is less than 128 bits.'));
        }
    }
}
