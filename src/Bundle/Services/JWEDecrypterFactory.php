<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Core\AlgorithmManagerFactory;
use Psr\EventDispatcher\EventDispatcherInterface;

final readonly class JWEDecrypterFactory
{
    public function __construct(
        private AlgorithmManagerFactory $algorithmManagerFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    public function create(array $encryptionAlgorithms): JWEDecrypter
    {
        $algorithmManager = $this->algorithmManagerFactory->create($encryptionAlgorithms);

        return new JWEDecrypter($algorithmManager, $this->eventDispatcher);
    }
}
