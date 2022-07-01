<?php

declare(strict_types=1);

namespace Jose\Component\Encryption;

use function array_key_exists;
use InvalidArgumentException;

/**
 * @internal
 */
final class Recipient
{
    public function __construct(
        private readonly array $header,
        private readonly ?string $encryptedKey
    ) {
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
        if (! $this->hasHeaderParameter($key)) {
            throw new InvalidArgumentException(sprintf('The header "%s" does not exist.', $key));
        }

        return $this->header[$key];
    }

    /**
     * Returns true if the recipient header contains the parameter with the specified key.
     *
     * @param string $key The key
     */
    public function hasHeaderParameter(string $key): bool
    {
        return array_key_exists($key, $this->header);
    }

    /**
     * Returns the encrypted key.
     */
    public function getEncryptedKey(): ?string
    {
        return $this->encryptedKey;
    }
}
