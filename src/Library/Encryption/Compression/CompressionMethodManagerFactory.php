<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Compression;

use InvalidArgumentException;

class CompressionMethodManagerFactory
{
    /**
     * @var CompressionMethod[]
     */
    private array $compressionMethods = [];

    /**
     * This method adds a compression method to this factory. The method is uniquely identified by an alias. This allows
     * the same method to be added twice (or more) using several configuration options.
     */
    public function add(string $alias, CompressionMethod $compressionMethod): void
    {
        $this->compressionMethods[$alias] = $compressionMethod;
    }

    /**
     * Returns the list of compression method aliases supported by the factory.
     *
     * @return string[]
     */
    public function aliases(): array
    {
        return array_keys($this->compressionMethods);
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
     * Creates a compression method manager using the compression methods identified by the given aliases. If one of the
     * aliases does not exist, an exception is thrown.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases): CompressionMethodManager
    {
        $compressionMethods = [];
        foreach ($aliases as $alias) {
            if (! isset($this->compressionMethods[$alias])) {
                throw new InvalidArgumentException(sprintf(
                    'The compression method with the alias "%s" is not supported.',
                    $alias
                ));
            }
            $compressionMethods[] = $this->compressionMethods[$alias];
        }

        return new CompressionMethodManager($compressionMethods);
    }
}
