<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;

final class KeyIdentifierAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if (! $jwk->has('kid')) {
            $bag->add(Message::medium('The parameter "kid" should be added.'));
        }
    }
}
