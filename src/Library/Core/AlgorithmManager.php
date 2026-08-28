<?php

declare(strict_types=1);

namespace Jose\Component\Core;

use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use function array_key_exists;
use function sprintf;
use function trigger_deprecation;

final class AlgorithmManager
{
    /**
     * @var array<string, Algorithm>
     */
    private array $algorithms = [];

    /**
     * @param Algorithm[] $algorithms
     */
    public function __construct(iterable $algorithms)
    {
        foreach ($algorithms as $algorithm) {
            $this->register($algorithm);
        }
    }

    /**
     * Returns true if the algorithm is supported.
     *
     * @param string $algorithm The algorithm
     */
    public function has(string $algorithm): bool
    {
        return array_key_exists($algorithm, $this->algorithms);
    }

    /**
     * @return array<string, Algorithm>
     */
    public function all(): array
    {
        return $this->algorithms;
    }

    /**
     * Returns the list of names of supported algorithms.
     *
     * @return string[]
     */
    public function list(): array
    {
        return array_keys($this->algorithms);
    }

    /**
     * Returns the algorithm if supported, otherwise throw an exception.
     *
     * @param string $algorithm The algorithm
     */
    public function get(string $algorithm): Algorithm
    {
        if (! $this->has($algorithm)) {
            throw new UnsupportedAlgorithmException(sprintf('The algorithm "%s" is not supported.', $algorithm));
        }

        return $this->algorithms[$algorithm];
    }

    /**
     * Returns a new manager that supports the algorithms of the current one plus the given ones.
     *
     * This method is immutable: the current manager is left untouched, so that a manager shared as a service keeps
     * expressing the policy it was built with. An algorithm whose name is already supported replaces the previous one
     * in the returned manager.
     */
    public function with(Algorithm ...$algorithms): self
    {
        $clone = clone $this;
        foreach ($algorithms as $algorithm) {
            $clone->register($algorithm);
        }

        return $clone;
    }

    /**
     * Adds an algorithm to the manager.
     *
     * @deprecated since 4.3.0, will be removed in 5.0.0. Use {@see self::with()} instead.
     */
    public function add(Algorithm $algorithm): void
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::add()" is deprecated and will be removed in 5.0.0. It widens the policy of a manager that is usually a shared service: use "%s::with()" instead, which returns a new manager and leaves the current one untouched.',
            self::class,
            self::class
        );

        $this->register($algorithm);
    }

    private function register(Algorithm $algorithm): void
    {
        $name = $algorithm->name();
        $this->algorithms[$name] = $algorithm;
    }
}
