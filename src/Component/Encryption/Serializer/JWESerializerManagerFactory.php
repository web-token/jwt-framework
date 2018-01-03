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

/**
 * Class JWESerializerManagerFactory.
 */
final class JWESerializerManagerFactory
{
    /**
     * @var JWESerializer[]
     */
    private $serializers = [];

    /**
     * @param string[] $names
     *
     * @return JWESerializerManager
     */
    public function create(array $names): JWESerializerManager
    {
        $serializers = [];
        foreach ($names as $name) {
            if (!array_key_exists($name, $this->serializers)) {
                throw new \InvalidArgumentException(sprintf('Unsupported serialiser "%s".', $name));
            }
            $serializers[] = $this->serializers[$name];
        }

        return JWESerializerManager::create($serializers);
    }

    /**
     * @return string[]
     */
    public function names(): array
    {
        return array_keys($this->serializers);
    }

    /**
     * @return JWESerializer[]
     */
    public function all(): array
    {
        return $this->serializers;
    }

    /**
     * @param JWESerializer $serializer
     *
     * @return JWESerializerManagerFactory
     */
    public function add(JWESerializer $serializer): self
    {
        $this->serializers[$serializer->name()] = $serializer;

        return $this;
    }
}
