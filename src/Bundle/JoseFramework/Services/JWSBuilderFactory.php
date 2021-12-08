<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWSBuilderFactory
{
    public function __construct(
        private AlgorithmManagerFactory $signatureAlgorithmManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * This method creates a JWSBuilder using the given algorithm aliases.
     *
     * @param string[] $algorithms
     */
    public function create(array $algorithms): JWSBuilder
    {
        $algorithmManager = $this->signatureAlgorithmManagerFactory->create($algorithms);

        return new JWSBuilder($algorithmManager, $this->eventDispatcher);
    }
}
