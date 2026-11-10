<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\BigInteger;
use Override;
use function is_string;

final readonly class RsaAnalyzer implements KeyAnalyzer
{
    #[Override]
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'RSA') {
            return;
        }

        $this->checkExponent($jwk, $bag);
        $this->checkModulus($jwk, $bag);
    }

    private function checkExponent(JWK $jwk, MessageBag $bag): void
    {
        $e = $jwk->get('e');
        if (! is_string($e)) {
            $bag->add(Message::high('The exponent is not valid.'));

            return;
        }
        $e = Base64UrlSafe::decodeNoPadding($e);
        if ($e === '') {
            $bag->add(Message::high('The exponent is not valid.'));

            return;
        }
        $exponent = BigInteger::createFromBinaryString($e);
        if ($exponent->lowerThan(BigInteger::createFromDecimal(65537))) {
            $bag->add(Message::high('The exponent is too low. It should be at least 65537.'));
        }
    }

    private function checkModulus(JWK $jwk, MessageBag $bag): void
    {
        $n = $jwk->get('n');
        if (! is_string($n)) {
            $bag->add(Message::high('The modulus is not valid.'));

            return;
        }
        $n = Base64UrlSafe::decodeNoPadding($n);
        if ($n === '') {
            $bag->add(Message::high('The modulus is not valid.'));

            return;
        }
        $modulus = BigInteger::createFromBinaryString($n);
        if ($modulus->get()->getBitLength() < 2048) {
            $bag->add(Message::high('The key length is less than 2048 bits.'));
        }
        if ($jwk->has('d') && (! $jwk->has('p') || ! $jwk->has('q') || ! $jwk->has('dp') || ! $jwk->has(
            'dq'
        ) || ! $jwk->has('qi'))) {
            $bag->add(
                Message::medium(
                    'The key is a private RSA key, but Chinese Remainder Theorem primes are missing. These primes are not mandatory, but signatures and decryption processes are faster when available.'
                )
            );
        }
    }
}
