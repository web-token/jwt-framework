<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\Core\Util\Base64UrlSafe;
use Override;
use function is_string;
use function sprintf;
use function strlen;

/**
 * Checks the structure of an Algorithm Key Pair key holding ML-DSA material (RFC 9964): the "alg" the type cannot do
 * without, a "pub" of the size of the parameter set, and a "priv" that is the 32-byte seed - the expanded private
 * key of FIPS 204 is not a representation the RFC allows.
 *
 * Whether "pub" is the key the seed expands to is not checked here: it takes OpenSSL, and the algorithms do it
 * before every signature.
 */
final readonly class MLDSAKeyAnalyzer implements KeyAnalyzer
{
    #[Override]
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== AKPKey::KEY_TYPE) {
            return;
        }
        $alg = $jwk->find('alg');
        if (! is_string($alg)) {
            $bag->add(Message::high('Invalid key. The parameter "alg" is required on an AKP key.'));

            return;
        }
        if (! isset(AKPKey::PUBLIC_KEY_LENGTHS[$alg])) {
            $bag->add(Message::high(sprintf('Invalid key. The algorithm "%s" is not an ML-DSA algorithm.', $alg)));

            return;
        }
        $pub = $jwk->find('pub');
        if (! is_string($pub)) {
            $bag->add(Message::high('Invalid key. The parameter "pub" is missing or not a string.'));
        } elseif (strlen(Base64UrlSafe::decodeNoPadding($pub)) !== AKPKey::PUBLIC_KEY_LENGTHS[$alg]) {
            $bag->add(Message::high(sprintf(
                'Invalid key. The parameter "pub" of an %s key shall be %d bytes.',
                $alg,
                AKPKey::PUBLIC_KEY_LENGTHS[$alg]
            )));
        }
        if (! $jwk->has('priv')) {
            return;
        }
        $priv = $jwk->find('priv');
        if (! is_string($priv)) {
            $bag->add(Message::high('Invalid key. The parameter "priv" shall be a string.'));
        } elseif (strlen(Base64UrlSafe::decodeNoPadding($priv)) !== AKPKey::SEED_LENGTH) {
            $bag->add(Message::high(sprintf(
                'Invalid key. The parameter "priv" of an ML-DSA key shall be the %d-byte seed.',
                AKPKey::SEED_LENGTH
            )));
        }
    }
}
