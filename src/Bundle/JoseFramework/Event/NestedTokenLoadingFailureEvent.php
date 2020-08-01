<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class NestedTokenLoadingFailureEvent extends Event
{
    /**
     * @var Throwable
     */
    private $throwable;

    /**
     * @var string
     */
    private $token;

    /**
     * @var JWKSet
     */
    private $signatureKeySet;

    /**
     * @var JWKSet
     */
    private $encryptionKeySet;

    public function __construct(string $token, JWKSet $signatureKeySet, JWKSet $encryptionKeySet, Throwable $throwable)
    {
        $this->throwable = $throwable;
        $this->token = $token;
        $this->signatureKeySet = $signatureKeySet;
        $this->encryptionKeySet = $encryptionKeySet;
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

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
