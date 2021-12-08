<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Compression;

use function array_key_exists;
use InvalidArgumentException;

class CompressionMethodManager
{
    /**
     * @var CompressionMethod[]
     */
    private array $compressionMethods = [];

    public function __construct(array $methods = [])
    {
        foreach ($methods as $method) {
            $this->add($method);
        }
    }

    /**
     * Returns true if the givn compression method is supported.
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->compressionMethods);
    }

    /**
     * This method returns the compression method with the given name. Throws an exception if the method is not
     * supported.
     *
     * @param string $name The name of the compression method
     */
    public function get(string $name): CompressionMethod
    {
        if (! $this->has($name)) {
            throw new InvalidArgumentException(sprintf('The compression method "%s" is not supported.', $name));
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
        return array_keys($this->compressionMethods);
    }

    /**
     * Add the given compression method to the manager.
     */
    protected function add(CompressionMethod $compressionMethod): void
    {
        $name = $compressionMethod->name();
        $this->compressionMethods[$name] = $compressionMethod;
    }
}
