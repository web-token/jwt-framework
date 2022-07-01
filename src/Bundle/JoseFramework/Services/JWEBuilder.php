<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEBuiltSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilder as BaseJWEBuilder;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class JWEBuilder extends BaseJWEBuilder
{
    public function __construct(
        AlgorithmManager $keyEncryptionKeyEncryptionAlgorithmManager,
        AlgorithmManager $contentEncryptionAlgorithmManager,
        CompressionMethodManager $compressionManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($keyEncryptionKeyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);
    }

    public function build(): JWE
    {
        try {
            $jwe = parent::build();
            $this->eventDispatcher->dispatch(new JWEBuiltSuccessEvent($jwe));

            return $jwe;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWEBuiltFailureEvent(
                $this->payload,
                $this->recipients,
                $this->sharedProtectedHeader,
                $this->sharedHeader,
                $this->aad,
                $throwable
            ));

            throw $throwable;
        }
    }
}
