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

use Jose\Bundle\JoseFramework\Event\NestedTokenIssuedEvent;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenBuilder as BaseNestedTokenBuilder;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Psr\EventDispatcher\EventDispatcherInterface;

final class NestedTokenBuilder extends BaseNestedTokenBuilder
{
    /**
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    public function __construct(JWEBuilder $jweBuilder, JWESerializerManager $jweSerializerManager, JWSBuilder $jwsBuilder, JWSSerializerManager $jwsSerializerManager, EventDispatcherInterface $eventDispatcher)
    {
        parent::__construct($jweBuilder, $jweSerializerManager, $jwsBuilder, $jwsSerializerManager);
        $this->eventDispatcher = $eventDispatcher;
    }

    public function create(string $payload, array $signatures, string $jws_serialization_mode, array $jweSharedProtectedHeader, array $jweSharedHeader, array $recipients, string $jwe_serialization_mode, ?string $aad = null): string
    {
        $nestedToken = parent::create($payload, $signatures, $jws_serialization_mode, $jweSharedProtectedHeader, $jweSharedHeader, $recipients, $jwe_serialization_mode, $aad);
        $this->eventDispatcher->dispatch(new NestedTokenIssuedEvent($nestedToken));

        return $nestedToken;
    }
}
