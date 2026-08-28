<?php

declare(strict_types=1);

namespace Jose\Component\Core;

use ArrayIterator;
use Countable;
use InvalidArgumentException;
use IteratorAggregate;
use JsonSerializable;
use Traversable;
use function array_key_exists;
use function count;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function sprintf;
use const COUNT_NORMAL;
use const JSON_THROW_ON_ERROR;

class JWKSet implements Countable, IteratorAggregate, JsonSerializable
{
    private array $keys = [];

    /**
     * @param JWK[] $keys
     */
    public function __construct(array $keys)
    {
        foreach ($keys as $key) {
            if (! $key instanceof JWK) {
                throw new InvalidArgumentException('Invalid list. Should only contains JWK objects');
            }

            $this->add($key);
        }
    }

    /**
     * Creates a JWKSet object using the given values.
     */
    public static function createFromKeyData(array $data): self
    {
        if (! isset($data['keys'])) {
            throw new InvalidArgumentException('Invalid data.');
        }
        if (! is_array($data['keys'])) {
            throw new InvalidArgumentException('Invalid data.');
        }

        $jwkset = new self([]);
        foreach ($data['keys'] as $key) {
            $jwkset->add(new JWK($key));
        }

        return $jwkset;
    }

    /**
     * Creates a JWKSet object using the given Json string.
     */
    public static function createFromJson(string $json): self
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($data)) {
            throw new InvalidArgumentException('Invalid argument.');
        }

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
     * Add key to store in the key set. This method is immutable and will return a new object. A key is never replaced:
     * adding a key that carries an already used "kid" appends it to the key set.
     */
    public function with(JWK $jwk): self
    {
        $clone = clone $this;
        $clone->add($jwk);

        return $clone;
    }

    /**
     * Remove key from the key set. This method is immutable and will return a new object.
     *
     * @param int|string $key Key to remove from the key set. When several keys share the same "kid", only the first
     * one is removed
     */
    public function without(int|string $key): self
    {
        $index = $this->indexOf($key);
        if ($index === null) {
            return $this;
        }

        $clone = clone $this;
        unset($clone->keys[$index]);

        return $clone;
    }

    /**
     * Returns true if the key set contains a key with the given index or, when a string is given, a key with that
     * "kid".
     */
    public function has(int|string $index): bool
    {
        return $this->indexOf($index) !== null;
    }

    /**
     * Returns the key with the given index. When several keys share the same "kid", the first one is returned. Throws
     * an exception if the index is not present in the key store.
     */
    public function get(int|string $index): JWK
    {
        $index = $this->indexOf($index);
        if ($index === null) {
            throw new InvalidArgumentException('Undefined index.');
        }

        return $this->keys[$index];
    }

    /**
     * Returns the values to be serialized.
     */
    public function jsonSerialize(): array
    {
        return [
            'keys' => array_values($this->keys),
        ];
    }

    /**
     * Returns the number of keys in the key set.
     *
     * @param int $mode
     */
    public function count($mode = COUNT_NORMAL): int
    {
        return count($this->keys, $mode);
    }

    /**
     * Try to find a key that fits on the selected requirements. Returns null if not found.
     *
     * @param string $type Must be 'sig' (signature) or 'enc' (encryption)
     * @param Algorithm|null $algorithm Specifies the algorithm to be used
     * @param array<string, mixed> $restrictions More restrictions such as 'kid' or 'kty'
     */
    public function selectKey(string $type, ?Algorithm $algorithm = null, array $restrictions = []): ?JWK
    {
        if (! in_array($type, ['enc', 'sig'], true)) {
            throw new InvalidArgumentException('Allowed key types are "sig" or "enc".');
        }

        $result = [];
        foreach ($this->keys as $key) {
            $ind = 0;

            $can_use = $this->canKeyBeUsedFor($type, $key);
            if ($can_use === false) {
                continue;
            }
            $ind += $can_use;

            $alg = $this->canKeyBeUsedWithAlgorithm($algorithm, $key);
            if ($alg === false) {
                continue;
            }
            $ind += $alg;

            if ($this->doesKeySatisfyRestrictions($restrictions, $key) === false) {
                continue;
            }

            $result[] = [
                'key' => $key,
                'ind' => $ind,
            ];
        }

        if (count($result) === 0) {
            return null;
        }

        usort($result, [$this, 'sortKeys']);

        return $result[0]['key'];
    }

    /**
     * Internal method only. Should not be used.
     *
     * @internal
     */
    public static function sortKeys(array $a, array $b): int
    {
        return $b['ind'] <=> $a['ind'];
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
     * Stores the given key. Keys carrying a "kid" are indexed by that "kid", unless that index is already in use. As
     * stated by the RFC7517 section 4.5, several keys of a key set may share the same "kid": such keys are appended to
     * the key set instead of replacing the ones already stored.
     */
    private function add(JWK $jwk): void
    {
        if ($jwk->has('kid')) {
            $kid = $jwk->get('kid');
            if ((is_string($kid) || is_int($kid)) && ! array_key_exists($kid, $this->keys)) {
                $this->keys[$kid] = $jwk;

                return;
            }
        }

        $this->keys[] = $jwk;
    }

    /**
     * Resolves the given index into an internal key of the key store, or null when the key set has no such key. A
     * string index that is not used as an index is compared against the "kid" of every key, so that keys sharing a
     * "kid" with an already indexed key remain reachable.
     */
    private function indexOf(int|string $index): int|string|null
    {
        if (array_key_exists($index, $this->keys)) {
            return $index;
        }
        if (is_int($index)) {
            return null;
        }
        foreach ($this->all() as $key => $jwk) {
            if ($jwk->has('kid') && $jwk->get('kid') === $index) {
                return $key;
            }
        }

        return null;
    }

    private function canKeyBeUsedFor(string $type, JWK $key): bool|int
    {
        if ($key->has('use')) {
            return $type === $key->get('use') ? 1 : false;
        }
        if ($key->has('key_ops')) {
            $key_ops = $key->get('key_ops');
            if (! is_array($key_ops) || $key_ops !== array_filter($key_ops, static fn (mixed $v): bool => is_string($v))) {
                throw new InvalidArgumentException(
                    'Invalid key parameter "key_ops". Should be a list of key operations'
                );
            }

            return $type === self::convertKeyOpsToKeyUse($key_ops) ? 1 : false;
        }

        return 0;
    }

    private function canKeyBeUsedWithAlgorithm(?Algorithm $algorithm, JWK $key): bool|int
    {
        if ($algorithm === null) {
            return 0;
        }
        if (! in_array($key->get('kty'), $algorithm->allowedKeyTypes(), true)) {
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
            if (! $key->has($k) || $v !== $key->get($k)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param string[] $key_ops
     */
    private static function convertKeyOpsToKeyUse(array $key_ops): string
    {
        return match (true) {
            in_array('verify', $key_ops, true), in_array('sign', $key_ops, true) => 'sig',
            in_array('encrypt', $key_ops, true), in_array('decrypt', $key_ops, true), in_array(
                'wrapKey',
                $key_ops,
                true
            ), in_array(
                'unwrapKey',
                $key_ops,
                true
            ), in_array('deriveKey', $key_ops, true), in_array('deriveBits', $key_ops, true) => 'enc',
            default => throw new InvalidArgumentException(sprintf(
                'Unsupported key operation value "%s"',
                implode(', ', $key_ops)
            )),
        };
    }
}
