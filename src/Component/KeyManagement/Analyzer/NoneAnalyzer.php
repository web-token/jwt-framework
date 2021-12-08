<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;

final class NoneAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'none') {
            return;
        }

        $bag->add(
            Message::high(
                'This key is a meant to be used with the algorithm "none". This algorithm is not secured and should be used with care.'
            )
        );
    }
}
