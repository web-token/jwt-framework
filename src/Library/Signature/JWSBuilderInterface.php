<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;

/**
 * Accumulates the payload and the signatures of a JWS, then computes them.
 *
 * The interface is implemented by JWSBuilder and by every object that decorates it. Decoration is the supported way
 * of plugging behaviour into the builder: JWSBuilder is annotated as final and will be final in 5.0.0.
 *
 * The deprecated create() of JWSBuilder is deliberately left out: the builder is immutable, hence there is no state
 * to reset, and the method is removed in 5.0.0.
 */
interface JWSBuilderInterface
{
    /**
     * Returns the algorithm manager associated to the builder.
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager;

    /**
     * Sets the payload. This method returns a new builder.
     */
    public function withPayload(string $payload, bool $isPayloadDetached = false): self;

    /**
     * Sets a payload that is already Base64Url encoded. This method returns a new builder.
     */
    public function withEncodedPayload(string $payload, bool $isPayloadDetached = false): self;

    /**
     * Adds the information needed to compute a signature. This method returns a new builder.
     *
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $header
     */
    public function addSignature(JWK $signatureKey, array $protectedHeader, array $header = []): self;

    /**
     * Computes all the signatures and returns the JWS object.
     */
    public function build(): JWS;
}
