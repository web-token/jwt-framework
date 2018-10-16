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

namespace Jose\Component\Signature\Algorithm;

use Base64Url\Base64Url;
use Jose\Component\Core\JWK;

abstract class HMAC implements SignatureAlgorithm
{
    public function allowedKeyTypes(): array
    {
        return ['oct'];
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        return \hash_equals($this->sign($key, $input), $signature);
    }

    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);

        return \hash_hmac($this->getHashAlgorithm(), $input, Base64Url::decode($key->get('k')), true);
    }

    protected function checkKey(JWK $key)
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        if (!$key->has('k')) {
            throw new \InvalidArgumentException('The key parameter "k" is missing.');
        }
    }

    abstract protected function getHashAlgorithm(): string;
}
