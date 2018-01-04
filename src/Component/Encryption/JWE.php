<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
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
    private $sharedHeader = [];

    /**
     * @var array
     */
    private $sharedProtectedHeader = [];

    /**
     * @var string|null
     */
    private $encodedSharedProtectedHeader = null;

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
     * @param array       $sharedHeader
     * @param array       $sharedProtectedHeader
     * @param null|string $encodedSharedProtectedHeader
     * @param array       $recipients
     */
    private function __construct(string $ciphertext, string $iv, string $tag, ?string $aad = null, array $sharedHeader = [], array $sharedProtectedHeader = [], ?string $encodedSharedProtectedHeader = null, array $recipients = [])
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

    /**
     * @param string      $ciphertext
     * @param string      $iv
     * @param string      $tag
     * @param null|string $aad
     * @param array       $sharedHeader
     * @param array       $sharedProtectedHeader
     * @param null|string $encodedSharedProtectedHeader
     * @param array       $recipients
     *
     * @return JWE
     */
    public static function create(string $ciphertext, string $iv, string $tag, ?string $aad = null, array $sharedHeader = [], array $sharedProtectedHeader = [], ?string $encodedSharedProtectedHeader = null, array $recipients = []): self
    {
        return new self($ciphertext, $iv, $tag, $aad, $sharedHeader, $sharedProtectedHeader, $encodedSharedProtectedHeader, $recipients);
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
    public function getEncodedSharedProtectedHeader(): string
    {
        return $this->encodedSharedProtectedHeader ?? '';
    }

    /**
     * @return array
     */
    public function getSharedProtectedHeader(): array
    {
        return $this->sharedProtectedHeader;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedProtectedHeaderParameter(string $key)
    {
        if ($this->hasSharedProtectedHeaderParameter($key)) {
            return $this->sharedProtectedHeader[$key];
        }

        throw new \InvalidArgumentException(sprintf('The shared protected header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedProtectedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->sharedProtectedHeader);
    }

    /**
     * @return array
     */
    public function getSharedHeader(): array
    {
        return $this->sharedHeader;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedHeaderParameter(string $key)
    {
        if ($this->hasSharedHeaderParameter($key)) {
            return $this->sharedHeader[$key];
        }

        throw new \InvalidArgumentException(sprintf('The shared header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->sharedHeader);
    }
}
