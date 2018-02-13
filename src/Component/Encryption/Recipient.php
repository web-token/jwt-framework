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
 * Class Recipient.
 */
final class Recipient
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
     *
     * @param array       $header
     * @param null|string $encryptedKey
     */
    private function __construct(array $header, ?string $encryptedKey)
    {
        $this->header = $header;
        $this->encryptedKey = $encryptedKey;
    }

    /**
     * @param array       $header
     * @param null|string $encryptedKey
     *
     * @return Recipient
     */
    public static function create(array $header, ?string $encryptedKey): self
    {
        return new self($header, $encryptedKey);
    }

    /**
     * @return array
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Returns the value of the unprotected header of the specified key.
     *
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getHeaderParameter(string $key)
    {
        if ($this->hasHeaderParameter($key)) {
            return $this->header[$key];
        }

        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->header);
    }

    /**
     * @return null|string
     */
    public function getEncryptedKey(): ?string
    {
        return $this->encryptedKey;
    }
}
