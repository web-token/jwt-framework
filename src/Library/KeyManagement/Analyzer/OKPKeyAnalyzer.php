<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use Override;
use function in_array;
use function is_string;
use function sprintf;
use function strlen;

/**
 * Checks the structure of an Octet Key Pair key (RFC 8037): a known curve, "x" and "d" of the size the curve
 * dictates, and an "alg" that matches the curve when the key carries one.
 *
 * The signature algorithms of the Edwards curves are fully-specified since RFC 9864: a key on Ed25519 belongs to
 * "Ed25519" (or the deprecated "EdDSA"), a key on Ed448 to "Ed448". The Montgomery curves are used by the ECDH-ES
 * family, whose identifiers are not curve-specific.
 */
final readonly class OKPKeyAnalyzer implements KeyAnalyzer
{
    private const SIGNATURE_ALGORITHMS = [
        OKPKey::CURVE_ED25519 => ['Ed25519', 'EdDSA'],
        OKPKey::CURVE_ED448 => ['Ed448'],
    ];

    #[Override]
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'OKP') {
            return;
        }
        $crv = $jwk->find('crv');
        if (! is_string($crv)) {
            $bag->add(Message::high('Invalid key. The component "crv" is missing.'));

            return;
        }
        if (! isset(OKPKey::KEY_SIZES[$crv])) {
            $bag->add(Message::high(sprintf('Invalid key. The curve "%s" is not supported.', $crv)));

            return;
        }
        $this->checkComponentSize($jwk, 'x', OKPKey::KEY_SIZES[$crv], $bag);
        if ($jwk->has('d')) {
            $this->checkComponentSize($jwk, 'd', OKPKey::KEY_SIZES[$crv], $bag);
        }
        $this->checkAlgorithm($jwk, $crv, $bag);
    }

    private function checkComponentSize(JWK $jwk, string $component, int $size, MessageBag $bag): void
    {
        $value = $jwk->find($component);
        if (! is_string($value)) {
            $bag->add(Message::high(sprintf('Invalid key. The component "%s" shall be a string.', $component)));

            return;
        }
        if (strlen(Base64UrlSafe::decodeNoPadding($value)) !== $size) {
            $bag->add(Message::high(sprintf(
                'Invalid key. The component "%s" size shall be %d bytes.',
                $component,
                $size
            )));
        }
    }

    private function checkAlgorithm(JWK $jwk, string $crv, MessageBag $bag): void
    {
        $alg = $jwk->find('alg');
        if (! is_string($alg)) {
            return;
        }
        $expected = self::SIGNATURE_ALGORITHMS[$crv] ?? [];
        if (in_array($alg, $expected, true)) {
            return;
        }
        $isSignatureAlgorithm = in_array($alg, array_merge(...array_values(self::SIGNATURE_ALGORITHMS)), true);
        if ($isSignatureAlgorithm && $expected !== []) {
            $bag->add(Message::high(sprintf(
                'Invalid key. The algorithm "%s" cannot be used with the curve "%s"; use "%s".',
                $alg,
                $crv,
                $expected[0]
            )));

            return;
        }
        if ($isSignatureAlgorithm || ($expected !== [] && str_starts_with($alg, 'ECDH-'))) {
            $bag->add(Message::high(sprintf(
                'Invalid key. The algorithm "%s" cannot be used with the curve "%s".',
                $alg,
                $crv
            )));
        }
    }
}
