<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Psr\EventDispatcher\EventDispatcherInterface;

final class NestedTokenLoaderFactory
{
    public function __construct(
        private readonly JWELoaderFactory $jweLoaderFactory,
        private readonly JWSLoaderFactory $jwsLoaderFactory,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
    }

    public function create(
        array $jweSerializers,
        array $keyEncryptionAlgorithms,
        array $contentEncryptionAlgorithms,
        array $compressionMethods,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers
    ): NestedTokenLoader {
        $jweLoader = $this->jweLoaderFactory->create(
            $jweSerializers,
            $keyEncryptionAlgorithms,
            $contentEncryptionAlgorithms,
            $compressionMethods,
            $jweHeaderCheckers
        );
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader, $this->eventDispatcher);
    }
}
