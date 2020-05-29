<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption;

use function array_key_exists;
use function count;
use InvalidArgumentException;
use Jose\Component\Core\JWT;

class JWE implements JWT
{
    /**
     * @var Recipient[]
     */
    private $recipients = [];

    /**
     * @var null|string
     */
    private $ciphertext;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var null|string
     */
    private $aad;

    /**
     * @var string
     */
    private $tag;

    /**
     * @var array
     */
    private $sharedHeader = [];

    /**
     * @var array
     */
    private $sharedProtectedHeader = [];

    /**
     * @var null|string
     */
    private $encodedSharedProtectedHeader;

    /**
     * @var null|string
     */
    private $payload;

    public function __construct(string $ciphertext, string $iv, string $tag, ?string $aad = null, array $sharedHeader = [], array $sharedProtectedHeader = [], ?string $encodedSharedProtectedHeader = null, array $recipients = [])
    {
        $this->ciphertext = $ciphertext;
        $this->iv = $iv;
        $this->aad = $aad;
        $this->tag = $tag;
        $this->sharedHeader = $sharedHeader;
        $this->sharedProtectedHeader = $sharedProtectedHeader;
        $this->encodedSharedProtectedHeader = $encodedSharedProtectedHeader;
        $this->recipients = $recipients;
    }

    public function getPayload(): ?string
    {
        return $this->payload;
    }

    /**
     * Set the payload.
     * This method is immutable and a new object will be returned.
     *
     * @return JWE
     */
    public function withPayload(string $payload): self
    {
        $clone = clone $this;
        $clone->payload = $payload;

        return $clone;
    }

    /**
     * Returns the number of recipients associated with the JWS.
     */
    public function countRecipients(): int
    {
        return count($this->recipients);
    }

    /**
     * Returns true is the JWE has already been encrypted.
     */
    public function isEncrypted(): bool
    {
        return null !== $this->getCiphertext();
    }

    /**
     * Returns the recipients associated with the JWS.
     *
     * @return Recipient[]
     */
    public function getRecipients(): array
    {
        return $this->recipients;
    }

    /**
     * Returns the recipient object at the given index.
     *
     * @throws InvalidArgumentException if the recipient ID does not exist
     */
    public function getRecipient(int $id): Recipient
    {
        if (!isset($this->recipients[$id])) {
            throw new InvalidArgumentException('The recipient does not exist.');
        }

        return $this->recipients[$id];
    }

    /**
     * Returns the ciphertext. This method will return null is the JWE has not yet been encrypted.
     *
     * @return null|string The cyphertext
     */
    public function getCiphertext(): ?string
    {
        return $this->ciphertext;
    }

    /**
     * Returns the Additional Authentication Data if available.
     */
    public function getAAD(): ?string
    {
        return $this->aad;
    }

    /**
     * Returns the Initialization Vector if available.
     */
    public function getIV(): ?string
    {
        return $this->iv;
    }

    /**
     * Returns the tag if available.
     */
    public function getTag(): ?string
    {
        return $this->tag;
    }

    /**
     * Returns the encoded shared protected header.
     */
    public function getEncodedSharedProtectedHeader(): string
    {
        return $this->encodedSharedProtectedHeader ?? '';
    }

    /**
     * Returns the shared protected header.
     */
    public function getSharedProtectedHeader(): array
    {
        return $this->sharedProtectedHeader;
    }

    /**
     * Returns the shared protected header parameter identified by the given key.
     * Throws an exception is the the parameter is not available.
     *
     * @param string $key The key
     *
     * @throws InvalidArgumentException if the shared protected header parameter does not exist
     *
     * @return null|mixed
     */
    public function getSharedProtectedHeaderParameter(string $key)
    {
        if (!$this->hasSharedProtectedHeaderParameter($key)) {
            throw new InvalidArgumentException(sprintf('The shared protected header "%s" does not exist.', $key));
        }

        return $this->sharedProtectedHeader[$key];
    }

    /**
     * Returns true if the shared protected header has the parameter identified by the given key.
     *
     * @param string $key The key
     */
    public function hasSharedProtectedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->sharedProtectedHeader);
    }

    /**
     * Returns the shared header.
     */
    public function getSharedHeader(): array
    {
        return $this->sharedHeader;
    }

    /**
     * Returns the shared header parameter identified by the given key.
     * Throws an exception is the the parameter is not available.
     *
     * @param string $key The key
     *
     * @throws InvalidArgumentException if the shared header parameter does not exist
     *
     * @return null|mixed
     */
    public function getSharedHeaderParameter(string $key)
    {
        if (!$this->hasSharedHeaderParameter($key)) {
            throw new InvalidArgumentException(sprintf('The shared header "%s" does not exist.', $key));
        }

        return $this->sharedHeader[$key];
    }

    /**
     * Returns true if the shared header has the parameter identified by the given key.
     *
     * @param string $key The key
     */
    public function hasSharedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->sharedHeader);
    }

    /**
     * This method splits the JWE into a list of JWEs.
     * It is only useful when the JWE contains more than one recipient (JSON General Serialization).
     *
     * @return JWE[]
     */
    public function split(): array
    {
        $result = [];
        foreach ($this->recipients as $recipient) {
            $result[] = new self(
                $this->ciphertext,
                $this->iv,
                $this->tag,
                $this->aad,
                $this->sharedHeader,
                $this->sharedProtectedHeader,
                $this->encodedSharedProtectedHeader,
                [$recipient]
            );
        }

        return $result;
    }
}
