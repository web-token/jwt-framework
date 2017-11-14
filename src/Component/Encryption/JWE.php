<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption;

use Jose\Component\Core\JWT;

/**
 * Class JWE.
 */
final class JWE implements JWT
{
    /**
     * @var Recipient[]
     */
    private $recipients = [];

    /**
     * @var string|null
     */
    private $ciphertext = null;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var string|null
     */
    private $aad = null;

    /**
     * @var string
     */
    private $tag;

    /**
     * @var array
     */
    private $sharedHeaders = [];

    /**
     * @var array
     */
    private $sharedProtectedHeaders = [];

    /**
     * @var string|null
     */
    private $encodedSharedProtectedHeaders = null;

    /**
     * @var string|null
     */
    private $payload = null;

    /**
     * JWE constructor.
     *
     * @param string      $ciphertext
     * @param string      $iv
     * @param string      $tag
     * @param null|string $aad
     * @param array       $sharedHeaders
     * @param array       $sharedProtectedHeaders
     * @param null|string $encodedSharedProtectedHeaders
     * @param array       $recipients
     */
    private function __construct(string $ciphertext, string $iv, string $tag, ?string $aad = null, array $sharedHeaders = [], array $sharedProtectedHeaders = [], ?string $encodedSharedProtectedHeaders = null, array $recipients = [])
    {
        $this->ciphertext = $ciphertext;
        $this->iv = $iv;
        $this->aad = $aad;
        $this->tag = $tag;
        $this->sharedHeaders = $sharedHeaders;
        $this->sharedProtectedHeaders = $sharedProtectedHeaders;
        $this->encodedSharedProtectedHeaders = $encodedSharedProtectedHeaders;
        $this->recipients = $recipients;
    }

    /**
     * @param string      $ciphertext
     * @param string      $iv
     * @param string      $tag
     * @param null|string $aad
     * @param array       $sharedHeaders
     * @param array       $sharedProtectedHeaders
     * @param null|string $encodedSharedProtectedHeaders
     * @param array       $recipients
     *
     * @return JWE
     */
    public static function create(string $ciphertext, string $iv, string $tag, ?string $aad = null, array $sharedHeaders = [], array $sharedProtectedHeaders = [], ?string $encodedSharedProtectedHeaders = null, array $recipients = []): self
    {
        return new self($ciphertext, $iv, $tag, $aad, $sharedHeaders, $sharedProtectedHeaders, $encodedSharedProtectedHeaders, $recipients);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): ?string
    {
        return $this->payload;
    }

    /**
     * @param string $payload
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
     *
     * @return int
     */
    public function countRecipients(): int
    {
        return count($this->recipients);
    }

    /**
     * @return bool
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
     * @param int $id
     *
     * @return Recipient
     */
    public function getRecipient(int $id): Recipient
    {
        if (!array_key_exists($id, $this->recipients)) {
            throw new \InvalidArgumentException('The recipient does not exist.');
        }

        return $this->recipients[$id];
    }

    /**
     * @return string|null The cyphertext
     */
    public function getCiphertext(): ?string
    {
        return $this->ciphertext;
    }

    /**
     * @return string|null
     */
    public function getAAD(): ?string
    {
        return $this->aad;
    }

    /**
     * @return string|null
     */
    public function getIV(): ?string
    {
        return $this->iv;
    }

    /**
     * @return string|null
     */
    public function getTag(): ?string
    {
        return $this->tag;
    }

    /**
     * @return string
     */
    public function getEncodedSharedProtectedHeaders(): string
    {
        return $this->encodedSharedProtectedHeaders ?? '';
    }

    /**
     * @return array
     */
    public function getSharedProtectedHeaders(): array
    {
        return $this->sharedProtectedHeaders;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedProtectedHeader(string $key)
    {
        if ($this->hasSharedProtectedHeader($key)) {
            return $this->sharedProtectedHeaders[$key];
        }

        throw new \InvalidArgumentException(sprintf('The shared protected header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedProtectedHeader(string $key): bool
    {
        return array_key_exists($key, $this->sharedProtectedHeaders);
    }

    /**
     * @return array
     */
    public function getSharedHeaders(): array
    {
        return $this->sharedHeaders;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedHeader(string $key)
    {
        if ($this->hasSharedHeader($key)) {
            return $this->sharedHeaders[$key];
        }

        throw new \InvalidArgumentException(sprintf('The shared header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedHeader(string $key): bool
    {
        return array_key_exists($key, $this->sharedHeaders);
    }
}
