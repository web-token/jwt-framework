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

/**
 * @internal
 */
class Recipient
{
    /**
     * @var array
     */
    private $header = [];

    /**
     * @var null|string
     */
    private $encryptedKey = null;

    /**
     * Recipient constructor.
     */
    private function __construct(array $header, ?string $encryptedKey)
    {
        $this->header = $header;
        $this->encryptedKey = $encryptedKey;
    }

    /**
     * Creates a recipient.
     * The creation of this object is meant to be used by the library, not by third party applications.
     *
     * @return Recipient
     */
    public static function create(array $header, ?string $encryptedKey): self
    {
        return new self($header, $encryptedKey);
    }

    /**
     * Returns the recipient header.
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Returns the value of the recipient header parameter with the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null
     */
    public function getHeaderParameter(string $key)
    {
        if ($this->hasHeaderParameter($key)) {
            return $this->header[$key];
        }

        throw new \InvalidArgumentException(\sprintf('The header "%s" does not exist.', $key));
    }

    /**
     * Returns true if the recipient header contains the parameter with the specified key.
     *
     * @param string $key The key
     */
    public function hasHeaderParameter(string $key): bool
    {
        return \array_key_exists($key, $this->header);
    }

    /**
     * Returns the encrypted key.
     */
    public function getEncryptedKey(): ?string
    {
        return $this->encryptedKey;
    }
}
