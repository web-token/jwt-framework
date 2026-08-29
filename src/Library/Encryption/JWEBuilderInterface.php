<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;

/**
 * Accumulates the payload, the headers and the recipients of a JWE, then encrypts them.
 *
 * The interface is implemented by JWEBuilder and by every object that decorates it. Decoration is the supported way of
 * plugging behaviour into the builder: JWEBuilder is annotated as final and will be final in 5.0.0.
 *
 * The deprecated create() of JWEBuilder is deliberately left out: the builder is immutable, hence there is no state to
 * reset, and the method is removed in 5.0.0.
 */
interface JWEBuilderInterface
{
    /**
     * Returns the key encryption algorithm manager.
     */
    public function getKeyEncryptionAlgorithmManager(): AlgorithmManager;

    /**
     * Returns the content encryption algorithm manager.
     */
    public function getContentEncryptionAlgorithmManager(): AlgorithmManager;

    /**
     * Sets the payload of the JWE to build. This method returns a new builder.
     */
    public function withPayload(string $payload): self;

    /**
     * Sets the Additional Authenticated Data of the JWE to build. This method returns a new builder.
     */
    public function withAAD(?string $aad): self;

    /**
     * Sets the shared protected header of the JWE to build. This method returns a new builder.
     *
     * @param array<string, mixed> $sharedProtectedHeader
     */
    public function withSharedProtectedHeader(array $sharedProtectedHeader): self;

    /**
     * Sets the shared header of the JWE to build. This method returns a new builder.
     *
     * @param array<string, mixed> $sharedHeader
     */
    public function withSharedHeader(array $sharedHeader): self;

    /**
     * Adds a recipient to the JWE to build. This method returns a new builder.
     *
     * @param array<string, mixed> $recipientHeader
     */
    public function addRecipient(JWK $recipientKey, array $recipientHeader = []): self;

    /**
     * Sets the sender key to be used instead of the internal generated key. This method returns a new builder.
     */
    public function withSenderKey(JWK $senderKey): self;

    /**
     * Encrypts the payload and returns the JWE object.
     */
    public function build(): JWE;
}
