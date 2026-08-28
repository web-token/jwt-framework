<?php

declare(strict_types=1);

namespace Jose\Component\Core;

use Jose\Component\Core\Util\AliasedRegistry;

/**
 * @see \Jose\Tests\Component\Core\AlgorithmManagerFactoryTest
 */
final class AlgorithmManagerFactory
{
    /**
     * @use AliasedRegistry<Algorithm>
     */
    use AliasedRegistry;

    /**
     * @param Algorithm[] $algorithms
     */
    public function __construct(iterable $algorithms = [])
    {
        foreach ($algorithms as $algorithm) {
            $this->add($algorithm->name(), $algorithm);
        }
    }

    /**
     * Adds an algorithm.
     *
     * Each algorithm is identified by an alias hence it is allowed to have the same algorithm twice (or more). This can
     * be helpful when an algorithm have several configuration options.
     */
    public function add(string $alias, Algorithm $algorithm): void
    {
        $this->register($alias, $algorithm);
    }

    /**
     * Create an algorithm manager using the given aliases.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): AlgorithmManager
    {
        return new AlgorithmManager($this->select($aliases, 'algorithm'));
    }
}
