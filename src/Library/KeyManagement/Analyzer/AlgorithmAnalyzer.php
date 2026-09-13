<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\OKPKey;
use Override;
use function sprintf;

/**
 * Checks the "alg" parameter of a key: it should be present, and it should not name a deprecated algorithm. The
 * polymorphic "EdDSA" is deprecated by RFC 9864 section 4.1.2 in favour of the fully-specified "Ed25519" and
 * "Ed448".
 */
final readonly class AlgorithmAnalyzer implements KeyAnalyzer
{
    #[Override]
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if (! $jwk->has('alg')) {
            $bag->add(Message::medium('The parameter "alg" should be added.'));

            return;
        }
        if ($jwk->find('alg') === 'EdDSA') {
            $replacement = $jwk->find('crv') === OKPKey::CURVE_ED448 ? 'Ed448' : 'Ed25519';
            $bag->add(Message::medium(sprintf(
                'The algorithm "EdDSA" is deprecated. Use the fully-specified "%s" algorithm instead.',
                $replacement
            )));
        }
    }
}
