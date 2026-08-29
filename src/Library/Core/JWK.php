<?php

declare(strict_types=1);

namespace Jose\Component\Core;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\Util\Base64UrlSafe;
use JsonSerializable;
use Override;
use function array_key_exists;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * A JSON Web Key.
 *
 * The parameters are stored as they were given: only the presence of "kty" is checked. The typed accessors - kty(),
 * alg(), use() and getString() - read a parameter and assert its type once, so that the callers do not have to write
 * the "has() then get() then is_string()" dance every time; find() returns null instead of throwing when a parameter
 * is absent. The class will be final and readonly in 5.0.0, where the parameters are validated against the key type
 * at construction time.
 *
 * @see \Jose\Tests\Component\Core\JWKTest
 */
class JWK implements JsonSerializable
{
    private array $values;

    /**
     * Creates a JWK object using the given values. The member "kty" is mandatory. Other members are NOT checked.
     */
    public function __construct(array $values)
    {
        if (! isset($values['kty'])) {
            throw new InvalidKeyException('The parameter "kty" is mandatory.');
        }
        $this->values = $values;
    }

    /**
     * Creates a JWK object using the given Json string.
     */
    public static function createFromJson(string $json): self
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($data)) {
            throw new InvalidArgumentException('Invalid argument.');
        }

        return new self($data);
    }

    /**
     * Returns the values to be serialized.
     */
    #[Override]
    public function jsonSerialize(): array
    {
        return $this->values;
    }

    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @return mixed|null
     */
    public function get(string $key)
    {
        if (! $this->has($key)) {
            throw new InvalidKeyException(sprintf('The value identified by "%s" does not exist.', $key));
        }

        return $this->values[$key];
    }

    /**
     * Get the value with a specific key, as a string.
     *
     * @param string $key The key
     *
     * @throws InvalidKeyException if the value does not exist or is not a string
     */
    public function getString(string $key): string
    {
        $value = $this->get($key);
        if (! is_string($value)) {
            throw new InvalidKeyException(sprintf('Invalid key parameter "%s". Should be a string.', $key));
        }

        return $value;
    }

    /**
     * Get the value with a specific key, or null when the JWK does not carry it.
     *
     * @param string $key The key
     */
    public function find(string $key): mixed
    {
        return $this->has($key) ? $this->values[$key] : null;
    }

    /**
     * The key type. The parameter is mandatory: a JWK cannot be created without one.
     *
     * @throws InvalidKeyException if the value is not a string
     */
    public function kty(): string
    {
        return $this->getString('kty');
    }

    /**
     * The algorithm the key is restricted to, or null when it is not restricted to any.
     *
     * @throws InvalidKeyException if the value is not a string
     */
    public function alg(): ?string
    {
        return $this->has('alg') ? $this->getString('alg') : null;
    }

    /**
     * The usage the key is restricted to - "sig" or "enc" - or null when it is not restricted to any.
     *
     * @throws InvalidKeyException if the value is not a string
     */
    public function use(): ?string
    {
        return $this->has('use') ? $this->getString('use') : null;
    }

    /**
     * Returns true if the JWK has the value identified by.
     *
     * @param string $key The key
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    /**
     * Get all values stored in the JWK object.
     *
     * @return array Values of the JWK object
     */
    public function all(): array
    {
        return $this->values;
    }

    /**
     * Returns the thumbprint of the key.
     *
     * @see https://tools.ietf.org/html/rfc7638
     */
    public function thumbprint(string $hash_algorithm): string
    {
        if (! in_array($hash_algorithm, hash_algos(), true)) {
            throw new UnsupportedAlgorithmException(sprintf('The hash algorithm "%s" is not supported.', $hash_algorithm));
        }
        $values = array_intersect_key($this->values, array_flip(['kty', 'n', 'e', 'crv', 'x', 'y', 'k']));
        ksort($values);
        $input = json_encode($values, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($input === false) {
            throw new InvalidKeyException('Unable to compute the key thumbprint');
        }

        return Base64UrlSafe::encodeUnpadded(hash($hash_algorithm, $input, true));
    }

    /**
     * Returns the associated public key.
     * This method has no effect for:
     * - public keys
     * - shared keys
     * - unknown keys.
     *
     * Known keys are "oct", "RSA", "EC" and "OKP".
     */
    public function toPublic(): self
    {
        $values = array_diff_key($this->values, array_flip(['p', 'd', 'q', 'dp', 'dq', 'qi']));

        return new self($values);
    }
}
