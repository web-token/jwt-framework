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

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\NestedToken\NestedTokenLoader as BaseNestedTokenLoader;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class NestedTokenLoader extends BaseNestedTokenLoader
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(JWELoader $jweLoader, JWSLoader $jwsLoader, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($jweLoader, $jwsLoader);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function load(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet, ?int &$signature = null): JWS
    {
        try {
            $jws = parent::load($token, $encryptionKeySet, $signatureKeySet, $signature);
            $this->eventDispatcher->dispatch(new NestedTokenLoadingSuccessEvent(
                $token,
                $jws,
                $signatureKeySet,
                $encryptionKeySet,
                $signature
            ));

            return $jws;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new NestedTokenLoadingFailureEvent(
                $token,
                $signatureKeySet,
                $encryptionKeySet,
                $throwable
            ));

            throw $throwable;
        }
    }
}
