<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWEBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEBuiltSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEBuilderInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * Dispatches an event whenever a JWE is built, without extending the builder it decorates.
 *
 * The decorator keeps the arguments it is given so that the failure event can be populated: the state of the decorated
 * builder is private and, unlike the deprecated JWEBuilder of this namespace, a decorator cannot read it. The
 * recipients it reports therefore describe the key and the header that were passed, and not the key encryption
 * algorithm the builder resolved from them.
 */
final readonly class EventDispatchingJWEBuilder implements JWEBuilderInterface
{
    /**
     * @param array<array{key: JWK, header: array<string, mixed>}> $recipients
     * @param array<string, mixed> $sharedProtectedHeader
     * @param array<string, mixed> $sharedHeader
     */
    public function __construct(
        private JWEBuilderInterface $builder,
        private EventDispatcherInterface $eventDispatcher,
        private ?string $payload = null,
        private array $recipients = [],
        private array $sharedProtectedHeader = [],
        private array $sharedHeader = [],
        private ?string $aad = null
    ) {
    }

    #[Override]
    public function getKeyEncryptionAlgorithmManager(): AlgorithmManager
    {
        return $this->builder->getKeyEncryptionAlgorithmManager();
    }

    #[Override]
    public function getContentEncryptionAlgorithmManager(): AlgorithmManager
    {
        return $this->builder->getContentEncryptionAlgorithmManager();
    }

    #[Override]
    public function withPayload(string $payload): self
    {
        return new self(
            $this->builder->withPayload($payload),
            $this->eventDispatcher,
            $payload,
            $this->recipients,
            $this->sharedProtectedHeader,
            $this->sharedHeader,
            $this->aad
        );
    }

    #[Override]
    public function withAAD(?string $aad): self
    {
        return new self(
            $this->builder->withAAD($aad),
            $this->eventDispatcher,
            $this->payload,
            $this->recipients,
            $this->sharedProtectedHeader,
            $this->sharedHeader,
            $aad
        );
    }

    #[Override]
    public function withSharedProtectedHeader(array $sharedProtectedHeader): self
    {
        return new self(
            $this->builder->withSharedProtectedHeader($sharedProtectedHeader),
            $this->eventDispatcher,
            $this->payload,
            $this->recipients,
            $sharedProtectedHeader,
            $this->sharedHeader,
            $this->aad
        );
    }

    #[Override]
    public function withSharedHeader(array $sharedHeader): self
    {
        return new self(
            $this->builder->withSharedHeader($sharedHeader),
            $this->eventDispatcher,
            $this->payload,
            $this->recipients,
            $this->sharedProtectedHeader,
            $sharedHeader,
            $this->aad
        );
    }

    #[Override]
    public function addRecipient(JWK $recipientKey, array $recipientHeader = []): self
    {
        return new self(
            $this->builder->addRecipient($recipientKey, $recipientHeader),
            $this->eventDispatcher,
            $this->payload,
            [...$this->recipients, [
                'key' => $recipientKey,
                'header' => $recipientHeader,
            ]],
            $this->sharedProtectedHeader,
            $this->sharedHeader,
            $this->aad
        );
    }

    #[Override]
    public function withSenderKey(JWK $senderKey): self
    {
        return new self(
            $this->builder->withSenderKey($senderKey),
            $this->eventDispatcher,
            $this->payload,
            $this->recipients,
            $this->sharedProtectedHeader,
            $this->sharedHeader,
            $this->aad
        );
    }

    #[Override]
    public function build(): JWE
    {
        try {
            $jwe = $this->builder->build();
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
