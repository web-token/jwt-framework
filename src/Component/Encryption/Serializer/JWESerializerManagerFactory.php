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

class JWESerializerManagerFactory
{
    /**
     * @var JWESerializer[]
     */
    private $serializers = [];

    /**
     * Creates a serializer manager factory using the given serializers.
     *
     * @param string[] $names
     */
    public function create(array $names): JWESerializerManager
    {
        $serializers = [];
        foreach ($names as $name) {
            if (!\array_key_exists($name, $this->serializers)) {
                throw new \InvalidArgumentException(\sprintf('Unsupported serializer "%s".', $name));
            }
            $serializers[] = $this->serializers[$name];
        }

        return JWESerializerManager::create($serializers);
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
     * Returns all serializers supported by this factory.
     *
     * @return JWESerializer[]
     */
    public function all(): array
    {
        return $this->serializers;
    }

    /**
     * Adds a serializer to the manager.
     *
     *
     * @return JWESerializerManagerFactory
     */
    public function add(JWESerializer $serializer): self
    {
        $this->serializers[$serializer->name()] = $serializer;

        return $this;
    }
}
