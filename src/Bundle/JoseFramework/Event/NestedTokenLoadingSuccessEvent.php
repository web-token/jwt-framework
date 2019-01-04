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

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Symfony\Component\EventDispatcher\Event;

final class NestedTokenLoadingSuccessEvent extends Event
{
    private $jws;

    private $signature;

    private $token;

    private $signatureKeySet;

    private $encryptionKeySet;

    public function __construct(string $token, JWS $jws, JWKSet $signatureKeySet, JWKSet $encryptionKeySet, int $signature)
    {
        $this->jws = $jws;
        $this->signature = $signature;
        $this->token = $token;
        $this->signatureKeySet = $signatureKeySet;
        $this->encryptionKeySet = $encryptionKeySet;
    }

    public function getJws(): JWS
    {
        return $this->jws;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getSignatureKeySet(): JWKSet
    {
        return $this->signatureKeySet;
    }

    public function getEncryptionKeySet(): JWKSet
    {
        return $this->encryptionKeySet;
    }

    public function getSignature(): int
    {
        return $this->signature;
    }
}
