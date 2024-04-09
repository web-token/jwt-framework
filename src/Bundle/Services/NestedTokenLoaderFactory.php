<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class NestedTokenLoaderFactory
{
    public function __construct(
        private readonly JWELoaderFactory $jweLoaderFactory,
        private readonly JWSLoaderFactory $jwsLoaderFactory,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    public function create(
        array $jweSerializers,
        array $encryptionAlgorithms,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers
    ): NestedTokenLoader {
        $jweLoader = $this->jweLoaderFactory->create($jweSerializers, $encryptionAlgorithms, $jweHeaderCheckers);
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader, $this->eventDispatcher);
    }
}
