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

use Jose\Bundle\JoseFramework\Event\JWELoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader as BaseJWELoader;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class JWELoader extends BaseJWELoader
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(JWESerializerManager $serializerManager, JWEDecrypter $jweDecrypter, ?HeaderCheckerManager $headerCheckerManager, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($serializerManager, $jweDecrypter, $headerCheckerManager);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        try {
            $jwe = parent::loadAndDecryptWithKeySet($token, $keyset, $recipient);
            $this->eventDispatcher->dispatch(new JWELoadingSuccessEvent(
                $token,
                $jwe,
                $keyset,
                $recipient
            ));

            return $jwe;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWELoadingFailureEvent(
                $token,
                $keyset,
                $throwable
            ));

            throw $throwable;
        }
    }
}
