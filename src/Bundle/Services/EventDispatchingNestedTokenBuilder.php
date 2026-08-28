<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenIssuedEvent;
use Jose\Component\NestedToken\NestedTokenBuilderInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Dispatches an event whenever a nested token is issued, without extending the builder it decorates.
 */
final readonly class EventDispatchingNestedTokenBuilder implements NestedTokenBuilderInterface
{
    public function __construct(
        private NestedTokenBuilderInterface $builder,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function create(
        string $payload,
        array $signatures,
        string $jws_serialization_mode,
        array $jweSharedProtectedHeader,
        array $jweSharedHeader,
        array $recipients,
        string $jwe_serialization_mode,
        ?string $aad = null
    ): string {
        $nestedToken = $this->builder->create(
            $payload,
            $signatures,
            $jws_serialization_mode,
            $jweSharedProtectedHeader,
            $jweSharedHeader,
            $recipients,
            $jwe_serialization_mode,
            $aad
        );
        $this->eventDispatcher->dispatch(new NestedTokenIssuedEvent($nestedToken));

        return $nestedToken;
    }
}
