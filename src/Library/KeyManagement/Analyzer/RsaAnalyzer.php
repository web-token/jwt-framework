<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Override;
use function is_string;
use function ord;
use function strlen;

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

    /**
     * The exponent is compared on its octets, without its leading zero octets: a value longer than three octets is at
     * least 2^24, so only a value of three octets or less is converted into an integer.
     */
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
        $e = ltrim($e, "\0");
        if (strlen($e) <= 3 && hexdec(bin2hex($e)) < 65537) {
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
        if (self::getBitLength($n) < 2048) {
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

    /**
     * Returns the bit length of a Base64urlUInt value (RFC 7518, section 2) from its octets, leading zero octets
     * ignored. The analyzed keys may come from a third party with a modulus of any length: converting it into a big
     * integer costs seconds to minutes without GMP, while this costs nothing.
     */
    private static function getBitLength(string $value): int
    {
        $value = ltrim($value, "\0");
        if ($value === '') {
            return 0;
        }

        return 8 * (strlen($value) - 1) + strlen(decbin(ord($value[0])));
    }
}
