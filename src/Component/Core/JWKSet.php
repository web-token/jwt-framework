<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use ArrayIterator;
use Assert\Assertion;
use Countable;
use InvalidArgumentException;
use IteratorAggregate;
use JsonSerializable;
use Traversable;

class JWKSet implements Countable, IteratorAggregate, JsonSerializable
{
    /**
     * @var array
     */
    private $keys = [];

    /**
     * JWKSet constructor.
     *
     * @param JWK[] $keys
     */
    private function __construct(array $keys)
    {
        $this->keys = $keys;
    }

    /**
     * Creates a JWKSet object using the given values.
     *
     * @return JWKSet
     */
    public static function createFromKeyData(array $data): self
    {
        Assertion::keyExists($data, 'keys', 'Invalid data.');
        Assertion::isArray($data['keys'], 'Invalid data.');

        $keys = [];
        foreach ($data['keys'] as $key) {
            $jwk = JWK::create($key);
            if ($jwk->has('kid')) {
                $keys[$jwk->get('kid')] = $jwk;

                continue;
            }
            $keys[] = $jwk;
        }

        return new self($keys);
    }

    /**
     * Creates a JWKSet object using the given JWK objects.
     *
     * @param JWK[] $keys
     *
     * @return JWKSet
     */
    public static function createFromKeys(array $keys): self
    {
        $keys = array_filter($keys, function () {
            return true;
        });
        foreach ($keys as $k => $v) {
            if ($v->has('kid')) {
                unset($keys[$k]);
                $keys[$v->get('kid')] = $v;
            }
        }

        return new self($keys);
    }

    /**
     * Creates a JWKSet object using the given Json string.
     *
     * @return JWKSet
     */
    public static function createFromJson(string $json): self
    {
        $data = json_decode($json, true);
        Assertion::isArray($data, 'Invalid argument.');

        return self::createFromKeyData($data);
    }

    /**
     * Returns an array of keys stored in the key set.
     *
     * @return JWK[]
     */
    public function all(): array
    {
        return $this->keys;
    }

    /**
     * Add key to store in the key set.
     * This method is immutable and will return a new object.
     *
     * @return JWKSet
     */
    public function with(JWK $jwk): self
    {
        $clone = clone $this;

        if ($jwk->has('kid')) {
            $clone->keys[$jwk->get('kid')] = $jwk;
        } else {
            $clone->keys[] = $jwk;
        }

        return $clone;
    }

    /**
     * Remove key from the key set.
     * This method is immutable and will return a new object.
     *
     * @param int|string $key Key to remove from the key set
     *
     * @return JWKSet
     */
    public function without($key): self
    {
        if (!$this->has($key)) {
            return $this;
        }

        $clone = clone $this;
        unset($clone->keys[$key]);

        return $clone;
    }

    /**
     * Returns true if the key set contains a key with the given index.
     *
     * @param int|string $index
     */
    public function has($index): bool
    {
        return \array_key_exists($index, $this->keys);
    }

    /**
     * Returns the key with the given index. Throws an exception if the index is not present in the key store.
     *
     * @param int|string $index
     */
    public function get($index): JWK
    {
        Assertion::true($this->has($index), 'Undefined index.');

        return $this->keys[$index];
    }

    /**
     * Returns the values to be serialized.
     */
    public function jsonSerialize(): array
    {
        return ['keys' => array_values($this->keys)];
    }

    /**
     * Returns the number of keys in the key set.
     *
     * @param int $mode
     */
    public function count($mode = COUNT_NORMAL): int
    {
        return \count($this->keys, $mode);
    }

    /**
     * Try to find a key that fits on the selected requirements.
     * Returns null if not found.
     *
     * @param string         $type         Must be 'sig' (signature) or 'enc' (encryption)
     * @param null|Algorithm $algorithm    Specifies the algorithm to be used
     * @param array          $restrictions More restrictions such as 'kid' or 'kty'
     */
    public function selectKey(string $type, ?Algorithm $algorithm = null, array $restrictions = []): ?JWK
    {
        Assertion::inArray($type, ['enc', 'sig'], 'Allowed key types are "sig" or "enc".');

        $result = [];
        foreach ($this->keys as $key) {
            $ind = 0;

            $can_use = $this->canKeyBeUsedFor($type, $key);
            if (false === $can_use) {
                continue;
            }
            $ind += $can_use;

            $alg = $this->canKeyBeUsedWithAlgorithm($algorithm, $key);
            if (false === $alg) {
                continue;
            }
            $ind += $alg;

            if (false === $this->doesKeySatisfyRestrictions($restrictions, $key)) {
                continue;
            }

            $result[] = ['key' => $key, 'ind' => $ind];
        }

        if (0 === \count($result)) {
            return null;
        }

        usort($result, [$this, 'sortKeys']);

        return $result[0]['key'];
    }

    /**
     * Internal method only. Should not be used.
     *
     * @internal
     * @internal
     */
    public static function sortKeys(array $a, array $b): int
    {
        if ($a['ind'] === $b['ind']) {
            return 0;
        }

        return ($a['ind'] > $b['ind']) ? -1 : 1;
    }

    /**
     * Internal method only. Should not be used.
     *
     * @internal
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->keys);
    }

    /**
     * @return bool|int
     */
    private function canKeyBeUsedFor(string $type, JWK $key)
    {
        if ($key->has('use')) {
            return $type === $key->get('use') ? 1 : false;
        }
        if ($key->has('key_ops')) {
            return $type === self::convertKeyOpsToKeyUse($key->get('use')) ? 1 : false;
        }

        return 0;
    }

    /**
     * @return bool|int
     */
    private function canKeyBeUsedWithAlgorithm(?Algorithm $algorithm, JWK $key)
    {
        if (null === $algorithm) {
            return 0;
        }
        if (!\in_array($key->get('kty'), $algorithm->allowedKeyTypes(), true)) {
            return false;
        }
        if ($key->has('alg')) {
            return $algorithm->name() === $key->get('alg') ? 2 : false;
        }

        return 1;
    }

    private function doesKeySatisfyRestrictions(array $restrictions, JWK $key): bool
    {
        foreach ($restrictions as $k => $v) {
            if (!$key->has($k) || $v !== $key->get($k)) {
                return false;
            }
        }

        return true;
    }

    private static function convertKeyOpsToKeyUse(string $key_ops): string
    {
        switch ($key_ops) {
            case 'verify':
            case 'sign':
                return 'sig';
            case 'encrypt':
            case 'decrypt':
            case 'wrapKey':
            case 'unwrapKey':
                return 'enc';
            default:
                throw new InvalidArgumentException(sprintf('Unsupported key operation value "%s"', $key_ops));
        }
    }
}
