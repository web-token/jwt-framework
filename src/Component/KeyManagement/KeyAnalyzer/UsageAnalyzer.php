<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Jose\Component\Core\JWK;

final class UsageAnalyzer implements KeyAnalyzer
{
    /**
     * {@inheritdoc}
     */
    public function analyze(JWK $jwk, MessageBag $bag)
    {
        if (!$jwk->has('use')) {
            $bag->add(Message::medium('The parameter "use" should be added.'));
        } elseif (!in_array($jwk->get('use'), ['sig', 'enc'])) {
            $bag->add(Message::high(sprintf('The parameter "use" has an unsupported value "%s". Please use "sig" (signature) or "enc" (encryption).', $jwk->get('use'))));
        }
        if ($jwk->has('key_ops') && !in_array($jwk->get('key_ops'), ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])) {
            $bag->add(Message::high(sprintf('The parameter "key_ops" has an unsupported value "%s". Please use one of the following values: %s.', $jwk->get('use'), implode(', ', ['verify', 'sign', 'encryp', 'decrypt', 'wrapKey', 'unwrapKey']))));
        }
    }
}
