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

class CompressionMethodManager
{
    /**
     * @var CompressionMethod[]
     */
    private $compressionMethods = [];

    /**
     * CompressionMethodManager constructor.
     *
     * @deprecated Will be private in v2.x. Please use CompressionManager::create() instead.
     */
    public function __construct()
    {
    }

    /**
     * This method creates a Compression Manager with the selected compression methods.
     *
     * @param CompressionMethod[] $methods
     *
     * @return CompressionMethodManager
     */
    public static function create(array $methods): self
    {
        $manager = new self();
        foreach ($methods as $method) {
            $manager->add($method);
        }

        return $manager;
    }

    /**
     * Add the given compression method to the manager.
     */
    protected function add(CompressionMethod $compressionMethod)
    {
        $name = $compressionMethod->name();
        if ($this->has($name)) {
            throw new \InvalidArgumentException(\sprintf('The compression method "%s" is already supported.', $name));
        }

        $this->compressionMethods[$name] = $compressionMethod;
    }

    /**
     * Returns true if the givn compression method is supported.
     */
    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->compressionMethods);
    }

    /**
     * This method returns the compression method with the given name.
     * Throws an exception if the method is not supported.
     *
     * @param string $name The name of the compression method
     */
    public function get(string $name): CompressionMethod
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException(\sprintf('The compression method "%s" is not supported.', $name));
        }

        return $this->compressionMethods[$name];
    }

    /**
     * Returns the list of compression method names supported by the manager.
     *
     * @return string[]
     */
    public function list(): array
    {
        return \array_keys($this->compressionMethods);
    }
}
