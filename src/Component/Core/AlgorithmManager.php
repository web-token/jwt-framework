<?php

declare(strict_types=1);

namespace Jose\Component\Core;

use function array_key_exists;
use InvalidArgumentException;

class AlgorithmManager
{
    private array $algorithms = [];

    /**
     * @param Algorithm[] $algorithms
     */
    public function __construct(array $algorithms)
    {
        foreach ($algorithms as $algorithm) {
            $this->add($algorithm);
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
            throw new InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $algorithm));
        }

        return $this->algorithms[$algorithm];
    }

    /**
     * Adds an algorithm to the manager.
     */
    public function add(Algorithm $algorithm): void
    {
        $name = $algorithm->name();
        $this->algorithms[$name] = $algorithm;
    }
}
