<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Brick\Math\BigInteger;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\NistCurve;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

final class ES256KeyAnalyzer implements KeyAnalyzer
{
    public function __construct()
    {
        if (! class_exists(NistCurve::class)) {
            throw new RuntimeException('Please install web-token/jwt-util-ecc to use this key analyzer');
        }
    }

    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'EC') {
            return;
        }
        if (! $jwk->has('crv')) {
            $bag->add(Message::high('Invalid key. The components "crv" is missing.'));

            return;
        }
        if ($jwk->get('crv') !== 'P-256') {
            return;
        }
        $x = Base64UrlSafe::decode($jwk->get('x'));
        $xLength = 8 * mb_strlen($x, '8bit');
        $y = Base64UrlSafe::decode($jwk->get('y'));
        $yLength = 8 * mb_strlen($y, '8bit');
        if ($yLength !== $xLength || $yLength !== 256) {
            $bag->add(Message::high('Invalid key. The components "x" and "y" size shall be 256 bits.'));
        }
        $xBI = BigInteger::fromBase(bin2hex($x), 16);
        $yBI = BigInteger::fromBase(bin2hex($y), 16);
        $curve = NistCurve::curve256();
        if (! $curve->contains($xBI, $yBI)) {
            $bag->add(Message::high('Invalid key. The point is not on the curve.'));
        }
    }
}
