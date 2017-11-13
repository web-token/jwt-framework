<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

/**
 * Class AlgorithmManagerFactory.
 */
final class AlgorithmManagerFactory
{
    /**
     * @var array
     */
    private $algorithms = [];

    /**
     * @param string             $alias
     * @param AlgorithmInterface $algorithm
     *
     * @return AlgorithmManagerFactory
     */
    public function add(string $alias, AlgorithmInterface $algorithm): self
    {
        if (array_key_exists($alias, $this->algorithms)) {
            throw new \InvalidArgumentException(sprintf('The alias "%s" already exists.', $alias));
        }
        $this->algorithms[$alias] = $algorithm;

        return $this;
    }

    /**
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->algorithms);
    }

    /**
     * @return AlgorithmInterface[]
     */
    public function all(): array
    {
        return $this->algorithms;
    }

    /**
     * @param string[] $aliases
     *
     * @return AlgorithmManager
     */
    public function create(array $aliases): AlgorithmManager
    {
        $algorithms = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->algorithms)) {
                $algorithms[] = $this->algorithms[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The algorithm with the alias "%s" is not supported.', $alias));
            }
        }

        return AlgorithmManager::create($algorithms);
    }
}
