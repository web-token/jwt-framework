<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Brick\Math\BigInteger;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Ecc\Curve;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function is_string;

abstract class ESKeyAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'EC') {
            return;
        }
        if (! $jwk->has('crv')) {
            $bag->add(Message::high('Invalid key. The components "crv" is missing.'));

            return;
        }
        if ($jwk->get('crv') !== $this->getCurveName()) {
            return;
        }
        $x = $jwk->get('x');
        if (! is_string($x)) {
            $bag->add(Message::high('Invalid key. The components "x" shall be a string.'));

            return;
        }
        $x = Base64UrlSafe::decodeNoPadding($x);
        $xLength = 8 * mb_strlen($x, '8bit');
        $y = $jwk->get('y');
        if (! is_string($y)) {
            $bag->add(Message::high('Invalid key. The components "y" shall be a string.'));

            return;
        }
        $y = Base64UrlSafe::decodeNoPadding($y);
        $yLength = 8 * mb_strlen($y, '8bit');
        if ($yLength !== $xLength || $yLength !== $this->getKeySize()) {
            $bag->add(
                Message::high(sprintf(
                    'Invalid key. The components "x" and "y" size shall be %d bits.',
                    $this->getKeySize()
                ))
            );
        }
        $xBI = BigInteger::fromBase(bin2hex($x), 16);
        $yBI = BigInteger::fromBase(bin2hex($y), 16);
        if (! $this->getCurve()->contains($xBI, $yBI)) {
            $bag->add(Message::high('Invalid key. The point is not on the curve.'));
        }
    }

    abstract protected function getAlgorithmName(): string;

    abstract protected function getCurveName(): string;

    abstract protected function getCurve(): Curve;

    abstract protected function getKeySize(): int;
}
