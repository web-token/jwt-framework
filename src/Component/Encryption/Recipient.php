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

/**
 * Class Recipient.
 */
final class Recipient
{
    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var null|string
     */
    private $encryptedKey = null;

    /**
     * Recipient constructor.
     *
     * @param array       $headers
     * @param null|string $encryptedKey
     */
    private function __construct(array $headers, ?string $encryptedKey)
    {
        $this->headers = $headers;
        $this->encryptedKey = $encryptedKey;
    }

    /**
     * @param array       $headers
     * @param null|string $encryptedKey
     *
     * @return Recipient
     */
    public static function create(array $headers = [], ?string $encryptedKey): self
    {
        return new self($headers, $encryptedKey);
    }

    /**
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeader(string $key)
    {
        if ($this->hasHeader($key)) {
            return $this->headers[$key];
        }

        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeader(string $key): bool
    {
        return array_key_exists($key, $this->headers);
    }

    /**
     * @return null|string
     */
    public function getEncryptedKey(): ?string
    {
        return $this->encryptedKey;
    }
}
