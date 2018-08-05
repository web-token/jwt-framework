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

namespace Jose\Component\Encryption\Serializer;

use Jose\Component\Encryption\JWE;

class JWESerializerManager
{
    /**
     * @var JWESerializer[]
     */
    private $serializers = [];

    /**
     * JWESerializerManager constructor.
     *
     * @param JWESerializer[] $serializers
     */
    private function __construct(array $serializers)
    {
        foreach ($serializers as $serializer) {
            $this->add($serializer);
        }
    }

    /**
     * Creates a serializer manager using the given serializers.
     *
     * @param JWESerializer[] $serializers
     *
     * @return JWESerializerManager
     */
    public static function create(array $serializers): self
    {
        return new self($serializers);
    }

    /**
     * Adds a serializer to the manager.
     *
     * @return JWESerializerManager
     */
    private function add(JWESerializer $serializer): self
    {
        $this->serializers[$serializer->name()] = $serializer;

        return $this;
    }

    /**
     * Return the serializer names supported by the manager.
     *
     * @deprecated Will be removed in v2.0. Please use names() instead.
     *
     * @return string[]
     */
    public function list(): array
    {
        return $this->names();
    }

    /**
     * Return the serializer names supported by the manager.
     *
     * @return string[]
     */
    public function names(): array
    {
        return \array_keys($this->serializers);
    }

    /**
     * Converts a JWE into a string.
     * Throws an exception if none of the serializer was able to convert the input.
     *
     * @throws \Exception
     */
    public function serialize(string $name, JWE $jws, ?int $recipientIndex = null): string
    {
        if (!\array_key_exists($name, $this->serializers)) {
            throw new \InvalidArgumentException(\sprintf('Unsupported serializer "%s".', $name));
        }

        return ($this->serializers[$name])->serialize($jws, $recipientIndex);
    }

    /**
     * Loads data and return a JWE object.
     * Throws an exception if none of the serializer was able to convert the input.
     *
     * @param string      $input A string that represents a JWE
     * @param string|null $name  the name of the serializer if the input is unserialized
     *
     * @throws \Exception
     */
    public function unserialize(string $input, ?string &$name = null): JWE
    {
        foreach ($this->serializers as $serializer) {
            try {
                $jws = $serializer->unserialize($input);
                $name = $serializer->name();

                return $jws;
            } catch (\InvalidArgumentException $e) {
                continue;
            }
        }

        throw new \InvalidArgumentException('Unsupported input.');
    }
}
