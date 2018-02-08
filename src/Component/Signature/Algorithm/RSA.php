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

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Signature\Util\RSA as JoseRSA;

abstract class RSA implements SignatureAlgorithm
{
    /**
     * @return string
     */
    abstract protected function getAlgorithm(): string;

    /**
     * @return int
     */
    abstract protected function getSignatureMethod(): int;

    /**
     * {@inheritdoc}
     */
    public function allowedKeyTypes(): array
    {
        return ['RSA'];
    }

    /**
     * {@inheritdoc}
     */
    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);
        $pub = RSAKey::createFromJWK($key->toPublic());

        return JoseRSA::verify($pub, $input, $signature, $this->getAlgorithm(), $this->getSignatureMethod());
    }

    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        if (!$key->has('d')) {
            throw new \InvalidArgumentException('The key is not a private key.');
        }

        $priv = RSAKey::createFromJWK($key);

        return JoseRSA::sign($priv, $input, $this->getAlgorithm(), $this->getSignatureMethod());
    }

    /**
     * @param JWK $key
     */
    private function checkKey(JWK $key)
    {
        if (!in_array($key->get('kty'), $this->allowedKeyTypes())) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        foreach (['n', 'e'] as $k) {
            if (!$key->has($k)) {
                throw new \InvalidArgumentException(sprintf('The key parameter "%s" is missing.', $k));
            }
        }
    }
}
