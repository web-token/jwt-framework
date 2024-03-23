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
        array $encryptionAlgorithms,
        null|array $contentEncryptionAlgorithms,
        null|array $compressionMethods,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers
    ): NestedTokenLoader {
        if ($contentEncryptionAlgorithms !== null) {
            $encryptionAlgorithms = array_merge($encryptionAlgorithms, $contentEncryptionAlgorithms);
        }
        $jweLoader = $this->jweLoaderFactory->create(
            $jweSerializers,
            $encryptionAlgorithms,
            null,
            $compressionMethods,
            $jweHeaderCheckers
        );
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader, $this->eventDispatcher);
    }
}
