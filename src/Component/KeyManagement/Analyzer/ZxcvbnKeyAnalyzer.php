<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use function is_string;
use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Throwable;
use ZxcvbnPhp\Zxcvbn;

final class ZxcvbnKeyAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'oct') {
            return;
        }
        $k = $jwk->get('k');
        if (! is_string($k)) {
            $bag->add(Message::high('The key is not valid'));

            return;
        }
        $k = Base64UrlSafe::decode($k);
        if (! class_exists(Zxcvbn::class)) {
            return;
        }
        $zxcvbn = new Zxcvbn();
        try {
            $strength = $zxcvbn->passwordStrength($k);
            switch (true) {
                case $strength['score'] < 3:
                    $bag->add(
                        Message::high(
                            'The octet string is weak and easily guessable. Please change your key as soon as possible.'
                        )
                    );

                    break;

                case $strength['score'] === 3:
                    $bag->add(Message::medium('The octet string is safe, but a longer key is preferable.'));

                    break;

                default:
                    break;
            }
        } catch (Throwable) {
            $bag->add(Message::medium('The test of the weakness cannot be performed.'));
        }
    }
}
