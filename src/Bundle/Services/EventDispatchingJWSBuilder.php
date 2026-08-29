<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSBuiltSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilderInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use function array_key_exists;

/**
 * Dispatches an event whenever a JWS is built, without extending the builder it decorates.
 *
 * The decorator keeps the arguments it is given so that the failure event can be populated: the state of the decorated
 * builder is private and, unlike the deprecated JWSBuilder of this namespace, a decorator cannot read it. The
 * signatures it reports therefore describe the key and the headers that were passed, and not the signature algorithm
 * the builder resolved from them.
 */
final readonly class EventDispatchingJWSBuilder implements JWSBuilderInterface
{
    /**
     * @param array<array{signature_key: JWK, protected_header: array<string, mixed>, header: array<string, mixed>}> $signatures
     */
    public function __construct(
        private JWSBuilderInterface $builder,
        private EventDispatcherInterface $eventDispatcher,
        private ?string $payload = null,
        private array $signatures = [],
        private bool $isPayloadDetached = false,
        private ?bool $isPayloadEncoded = null
    ) {
    }

    #[Override]
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->builder->getSignatureAlgorithmManager();
    }

    #[Override]
    public function withPayload(string $payload, bool $isPayloadDetached = false): self
    {
        return new self(
            $this->builder->withPayload($payload, $isPayloadDetached),
            $this->eventDispatcher,
            $payload,
            $this->signatures,
            $isPayloadDetached,
            $this->isPayloadEncoded
        );
    }

    #[Override]
    public function withEncodedPayload(string $payload, bool $isPayloadDetached = false): self
    {
        return new self(
            $this->builder->withEncodedPayload($payload, $isPayloadDetached),
            $this->eventDispatcher,
            Base64UrlSafe::decodeNoPadding($payload),
            $this->signatures,
            $isPayloadDetached,
            $this->isPayloadEncoded
        );
    }

    #[Override]
    public function addSignature(JWK $signatureKey, array $protectedHeader, array $header = []): self
    {
        $builder = $this->builder->addSignature($signatureKey, $protectedHeader, $header);

        return new self(
            $builder,
            $this->eventDispatcher,
            $this->payload,
            [...$this->signatures, [
                'signature_key' => $signatureKey,
                'protected_header' => $protectedHeader,
                'header' => $header,
            ]],
            $this->isPayloadDetached,
            $this->isPayloadEncoded ?? (! array_key_exists('b64', $protectedHeader) || $protectedHeader['b64'] === true)
        );
    }

    #[Override]
    public function build(): JWS
    {
        try {
            $jws = $this->builder->build();
            $this->eventDispatcher->dispatch(new JWSBuiltSuccessEvent($jws));

            return $jws;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWSBuiltFailureEvent(
                $this->payload,
                $this->signatures,
                $this->isPayloadDetached,
                $this->isPayloadEncoded,
                $throwable
            ));

            throw $throwable;
        }
    }
}
