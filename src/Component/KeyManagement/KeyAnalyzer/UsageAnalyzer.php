<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Jose\Component\Core\JWK;

/**
 * Class UsageAnalyzer.
 */
final class UsageAnalyzer implements JWKAnalyzer
{
    /**
     * {@inheritdoc}
     */
    public function analyze(JWK $jwk, array &$messages)
    {
        if (!$jwk->has('use')) {
            $messages[] = 'The parameter "use" should be added.';
        } elseif (!in_array($jwk->get('use'), ['sig', 'enc'])) {
            $messages[] = sprintf('The parameter "use" has an unsupported value "%s". Please use "sig" (signature) or "enc" (encryption).', $jwk->get('use'));
        }
        if ($jwk->has('key_ops') && !in_array($jwk->get('key_ops'), ['sig', 'enc'])) {
            $messages[] = sprintf('The parameter "key_ops" has an unsupported value "%s". Please use one of the following values: %s.', $jwk->get('use'), implode(', ', ['verify', 'sign', 'encryp', 'decrypt', 'wrapKey', 'unwrapKey']));
        }
    }
}
