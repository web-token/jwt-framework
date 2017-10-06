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

namespace Jose\Component\Encryption\Compression;

/**
 * Class CompressionMethodManager.
 */
final class CompressionMethodManager
{
    /**
     * @var CompressionMethodInterface[]
     */
    private $compressionMethods = [];

    /**
     * @param CompressionMethodInterface[] $methods
     *
     * @return CompressionMethodManager
     */
    public static function create(array $methods): CompressionMethodManager
    {
        $manager = new self();
        foreach ($methods as $method) {
            $manager->add($method);
        }

        return $manager;
    }

    /**
     * @param CompressionMethodInterface $compressionMethod
     */
    protected function add(CompressionMethodInterface $compressionMethod)
    {
        $name = $compressionMethod->name();
        if ($this->has($name)) {
            throw new \InvalidArgumentException(sprintf('The compression method "%s" is already supported.', $name));
        }

        $this->compressionMethods[$name] = $compressionMethod;
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->compressionMethods);
    }

    /**
     * This method will try to find a CompressionInterface object able to support the compression method.
     *
     * @param string $name The name of the compression method
     *
     * @return CompressionMethodInterface
     */
    public function get(string $name): CompressionMethodInterface
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException(sprintf('The compression method "%s" is not supported.', $name));
        }

        return $this->compressionMethods[$name];
    }

    /**
     * @return string[]
     */
    public function list(): array
    {
        return array_keys($this->compressionMethods);
    }
}
