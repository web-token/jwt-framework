<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;

final class HS384KeyAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'oct') {
            return;
        }
        if (! $jwk->has('alg') || $jwk->get('alg') !== 'HS384') {
            return;
        }
        $k = Base64UrlSafe::decode($jwk->get('k'));
        $kLength = 8 * mb_strlen($k, '8bit');
        if ($kLength < 384) {
            $bag->add(Message::high('HS384 algorithm requires at least 384 bits key length.'));
        }
    }
}
