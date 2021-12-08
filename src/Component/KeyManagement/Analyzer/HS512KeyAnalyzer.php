<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;

final class HS512KeyAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'oct') {
            return;
        }
        if (! $jwk->has('alg') || $jwk->get('alg') !== 'HS512') {
            return;
        }
        $k = Base64UrlSafe::decode($jwk->get('k'));
        $kLength = 8 * mb_strlen($k, '8bit');
        if ($kLength < 512) {
            $bag->add(Message::high('HS512 algorithm requires at least 512 bits key length.'));
        }
    }
}
