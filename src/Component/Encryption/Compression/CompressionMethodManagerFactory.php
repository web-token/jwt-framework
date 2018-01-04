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

/**
 * Class CompressionMethodManagerFactory.
 */
final class CompressionMethodManagerFactory
{
    /**
     * @var CompressionMethod[]
     */
    private $compressionMethods = [];

    /**
     * @param string            $alias
     * @param CompressionMethod $compressionMethod
     *
     * @return CompressionMethodManagerFactory
     */
    public function add(string $alias, CompressionMethod $compressionMethod): self
    {
        if (array_key_exists($alias, $this->compressionMethods)) {
            throw new \InvalidArgumentException(sprintf('The alias "%s" already exists.', $alias));
        }
        $this->compressionMethods[$alias] = $compressionMethod;

        return $this;
    }

    /**
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->compressionMethods);
    }

    /**
     * @return CompressionMethod[]
     */
    public function all(): array
    {
        return $this->compressionMethods;
    }

    /**
     * @param string[] $aliases
     *
     * @return CompressionMethodManager
     */
    public function create(array $aliases): CompressionMethodManager
    {
        $compressionMethods = [];
        foreach ($aliases as $alias) {
            if (array_key_exists($alias, $this->compressionMethods)) {
                $compressionMethods[] = $this->compressionMethods[$alias];
            } else {
                throw new \InvalidArgumentException(sprintf('The compression method with the alias "%s" is not supported.', $alias));
            }
        }

        return CompressionMethodManager::create($compressionMethods);
    }
}
