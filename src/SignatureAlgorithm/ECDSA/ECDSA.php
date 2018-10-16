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
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\ECSignature;

abstract class ECDSA implements SignatureAlgorithm
{
    public function __construct()
    {
        if (!\defined('OPENSSL_KEYTYPE_EC')) {
            throw new \RuntimeException('Elliptic Curve key type not supported by your environment.');
        }
    }

    public function allowedKeyTypes(): array
    {
        return ['EC'];
    }

    public function sign(JWK $key, string $input): string
    {
        $this->checkKey($key);
        if (!$key->has('d')) {
            throw new \InvalidArgumentException('The EC key is not private');
        }

        $pem = ECKey::convertPrivateKeyToPEM($key);
        $result = \openssl_sign($input, $signature, $pem, $this->getHashAlgorithm());
        if (false === $result) {
            throw new \RuntimeException('Signature failed.');
        }

        return ECSignature::fromDER($signature, $this->getSignaturePartLength());
    }

    public function verify(JWK $key, string $input, string $signature): bool
    {
        $this->checkKey($key);

        try {
            $der = ECSignature::toDER($signature, $this->getSignaturePartLength());
            $pem = ECKey::convertPublicKeyToPEM($key);

            return 1 === \openssl_verify($input, $der, $pem, $this->getHashAlgorithm());
        } catch (\Exception $e) {
            return false;
        }
    }

    abstract protected function getHashAlgorithm(): string;

    abstract protected function getSignaturePartLength(): int;

    private function checkKey(JWK $key)
    {
        if (!\in_array($key->get('kty'), $this->allowedKeyTypes(), true)) {
            throw new \InvalidArgumentException('Wrong key type.');
        }
        foreach (['x', 'y', 'crv'] as $k) {
            if (!$key->has($k)) {
                throw new \InvalidArgumentException(\sprintf('The key parameter "%s" is missing.', $k));
            }
        }
    }
}
