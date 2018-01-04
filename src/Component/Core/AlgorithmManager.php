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
 * Class AlgorithmManager.
 */
final class AlgorithmManager
{
    /**
     * @var array
     */
    private $algorithms = [];

    /**
     * AlgorithmManager constructor.
     *
     * @param Algorithm[] $algorithms
     */
    private function __construct(array $algorithms)
    {
        foreach ($algorithms as $algorithm) {
            $this->add($algorithm);
        }
    }

    /**
     * @param Algorithm[] $algorithms
     *
     * @return AlgorithmManager
     */
    public static function create(array $algorithms): self
    {
        return new self($algorithms);
    }

    /**
     * @param string $algorithm The algorithm
     *
     * @return bool Returns true if the algorithm is supported
     */
    public function has(string $algorithm): bool
    {
        return array_key_exists($algorithm, $this->algorithms);
    }

    /**
     * @return string[] Returns the list of names of supported algorithms
     */
    public function list(): array
    {
        return array_keys($this->algorithms);
    }

    /**
     * @param string $algorithm The algorithm
     *
     * @return Algorithm Returns JWAInterface object if the algorithm is supported, else null
     */
    public function get(string $algorithm): Algorithm
    {
        if (!$this->has($algorithm)) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $algorithm));
        }

        return $this->algorithms[$algorithm];
    }

    /**
     * @param Algorithm $algorithm
     *
     * @return AlgorithmManager
     */
    private function add(Algorithm $algorithm): self
    {
        $name = $algorithm->name();
        $this->algorithms[$name] = $algorithm;

        return $this;
    }
}
