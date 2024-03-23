<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class JWEBuilderFactory
{
    public function __construct(
        private AlgorithmManagerFactory $algorithmManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * This method creates a JWEBuilder using the given algorithm aliases.
     *
     * @param string[] $encryptionAlgorithms
     */
    public function create(array $encryptionAlgorithms): JWEBuilder
    {
        $algorithmManager = $this->algorithmManagerFactory->create($encryptionAlgorithms);

        return new JWEBuilder($algorithmManager, $this->eventDispatcher);
    }
}
