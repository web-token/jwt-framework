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

namespace Jose\Component\Encryption\Compression;

class CompressionMethodManagerFactory
{
    /**
     * @var CompressionMethod[]
     */
    private $compressionMethods = [];

    /**
     * This method adds a compression method to this factory.
     * The method is uniquely identified by an alias. This allows the same method to be added twice (or more)
     * using several configuration options.
     *
     * @return CompressionMethodManagerFactory
     */
    public function add(string $alias, CompressionMethod $compressionMethod): self
    {
        if (\array_key_exists($alias, $this->compressionMethods)) {
            throw new \InvalidArgumentException(\sprintf('The alias "%s" already exists.', $alias));
        }
        $this->compressionMethods[$alias] = $compressionMethod;

        return $this;
    }

    /**
     * Returns the list of compression method aliases supported by the factory.
     *
     * @return string[]
     */
    public function aliases(): array
    {
        return \array_keys($this->compressionMethods);
    }

    /**
     * Returns all compression methods supported by this factory.
     *
     * @return CompressionMethod[]
     */
    public function all(): array
    {
        return $this->compressionMethods;
    }

    /**
     * Creates a compression method manager using the compression methods identified by the given aliases.
     * If one of the aliases does not exist, an exception is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): CompressionMethodManager
    {
        $compressionMethods = [];
        foreach ($aliases as $alias) {
            if (\array_key_exists($alias, $this->compressionMethods)) {
                $compressionMethods[] = $this->compressionMethods[$alias];
            } else {
                throw new \InvalidArgumentException(\sprintf('The compression method with the alias "%s" is not supported.', $alias));
            }
        }

        return CompressionMethodManager::create($compressionMethods);
    }
}
