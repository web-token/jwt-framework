<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidArgumentException;
use function is_string;
use function sprintf;

/**
 * Common implementation of the "alias => object" registry every factory of this library is built on: the algorithm
 * manager factory, the header and claim checker manager factories and the JWS/JWE serializer manager factories.
 *
 * Those factories keep their own public API: this trait only holds the registered objects and provides the lookup they
 * all need, so that an unknown alias is reported the same way everywhere.
 *
 * @internal
 *
 * @template T of object
 */
trait AliasedRegistry
{
    /**
     * @var array<string, T>
     */
    private array $items = [];

    /**
     * Returns the list of aliases supported by this factory.
     *
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->items);
    }

    /**
     * Returns all the objects supported by this factory. This is an associative array whose keys are the aliases.
     *
     * @return array<string, T>
     */
    public function all(): array
    {
        return $this->items;
    }

    /**
     * Registers an object under the given alias. The same object may be registered twice (or more) under distinct
     * aliases, which is helpful when it has several configuration options.
     *
     * @param T $item
     */
    private function register(string $alias, object $item): void
    {
        $this->items[$alias] = $item;
    }

    /**
     * Returns the objects registered under the given aliases, in that order.
     *
     * The label is the human readable name of what the registry holds ("algorithm", "claim checker"...). It is only
     * used to build the error message. The exception class is the one the factory reported before the registry was
     * shared.
     *
     * @param string[] $aliases
     * @param class-string<InvalidArgumentException> $exceptionClass
     *
     * @return list<T>
     */
    private function select(
        array $aliases,
        string $label,
        string $exceptionClass = InvalidArgumentException::class
    ): array {
        $items = [];
        foreach ($aliases as $alias) {
            if (! is_string($alias)) {
                throw new $exceptionClass(sprintf('Invalid %s alias.', $label));
            }
            if (! isset($this->items[$alias])) {
                throw new $exceptionClass(sprintf(
                    'The %s with the alias "%s" is not supported.',
                    $label,
                    $alias
                ));
            }
            $items[] = $this->items[$alias];
        }

        return $items;
    }
}
