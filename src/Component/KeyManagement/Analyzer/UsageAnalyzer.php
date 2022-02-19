<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use function in_array;
use Jose\Component\Core\JWK;

final class UsageAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if (! $jwk->has('use')) {
            $bag->add(Message::medium('The parameter "use" should be added.'));
        } elseif (! in_array($jwk->get('use'), ['sig', 'enc'], true)) {
            $bag->add(
                Message::high(sprintf(
                    'The parameter "use" has an unsupported value "%s". Please use "sig" (signature) or "enc" (encryption).',
                    $jwk->get('use')
                ))
            );
        }
        if ($jwk->has('key_ops') && ! in_array(
            $jwk->get('key_ops'),
            ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
            true
        )) {
            $bag->add(
                Message::high(sprintf(
                    'The parameter "key_ops" has an unsupported value "%s". Please use one of the following values: %s.',
                    $jwk->get('key_ops'),
                    implode(', ', ['verify', 'sign', 'encryp', 'decrypt', 'wrapKey', 'unwrapKey'])
                ))
            );
        }
    }
}
