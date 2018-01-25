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

namespace Jose\Component\Core;

/**
 * Class JWKSet.
 */
final class JWKSet implements \Countable, \IteratorAggregate, \JsonSerializable
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
     * @param array $data
     *
     * @return JWKSet
     */
    public static function createFromKeyData(array $data): self
    {
        if (!array_key_exists('keys', $data) || !is_array($data['keys'])) {
            throw new \InvalidArgumentException('Invalid data.');
        }

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
     * @param string $json
     *
     * @return JWKSet
     */
    public static function createFromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new \InvalidArgumentException('Invalid argument.');
        }

        return self::createFromKeyData($data);
    }

    /**
     * Returns all keys in the key set.
     *
     * @return JWK[] An array of keys stored in the key set
     */
    public function all(): array
    {
        return $this->keys;
    }

    /**
     * Add key in the key set.
     *
     * @param JWK $jwk A key to store in the key set
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
     * @param int|string $index
     *
     * @return bool
     */
    public function has($index): bool
    {
        return array_key_exists($index, $this->keys);
    }

    /**
     * @param int|string $index
     *
     * @return JWK
     */
    public function get($index): JWK
    {
        if (!$this->has($index)) {
            throw new \InvalidArgumentException('Undefined index.');
        }

        return $this->keys[$index];
    }

    /**
     * @return array
     */
    public function jsonSerialize(): array
    {
        return ['keys' => $this->keys];
    }

    /**
     * @param int $mode
     *
     * @return int
     */
    public function count($mode = COUNT_NORMAL): int
    {
        return count($this->keys, $mode);
    }

    /**
     * @param string         $type         Must be 'sig' (signature) or 'enc' (encryption)
     * @param Algorithm|null $algorithm    Specifies the algorithm to be used
     * @param array          $restrictions More restrictions such as 'kid' or 'kty'
     *
     * @return JWK|null
     */
    public function selectKey(string $type, ?Algorithm $algorithm = null, array $restrictions = []): ?JWK
    {
        if (!in_array($type, ['enc', 'sig'])) {
            throw new \InvalidArgumentException('Allowed key types are "sig" or "enc".');
        }

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

        if (empty($result)) {
            return null;
        }

        usort($result, [$this, 'sortKeys']);

        return $result[0]['key'];
    }

    /**
     * @param string $type
     * @param JWK    $key
     *
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
     * @param null|Algorithm $algorithm
     * @param JWK            $key
     *
     * @return bool|int
     */
    private function canKeyBeUsedWithAlgorithm(?Algorithm $algorithm, JWK $key)
    {
        if (null === $algorithm) {
            return 0;
        }
        if (!in_array($key->get('kty'), $algorithm->allowedKeyTypes())) {
            return false;
        }
        if ($key->has('alg')) {
            return $algorithm->name() === $key->get('alg') ? 2 : false;
        }

        return 1;
    }

    /**
     * @param array $restrictions
     * @param JWK   $key
     *
     * @return bool
     */
    private function doesKeySatisfyRestrictions(array $restrictions, JWK $key): bool
    {
        foreach ($restrictions as $k => $v) {
            if (!$key->has($k) || $v !== $key->get($k)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param string $key_ops
     *
     * @return string
     */
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
                throw new \InvalidArgumentException(sprintf('Unsupported key operation value "%s"', $key_ops));
        }
    }

    /**
     * @param array $a
     * @param array $b
     *
     * @return int
     *
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
     * {@inheritdoc}
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->keys);
    }
}
