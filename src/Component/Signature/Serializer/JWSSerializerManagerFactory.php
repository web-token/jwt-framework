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

namespace Jose\Component\Signature\Serializer;

/**
 * Class JWSSerializerManagerFactory.
 */
final class JWSSerializerManagerFactory
{
    /**
     * @var JWSSerializerInterface[]
     */
    private $serializers = [];

    /**
     * @param string[] $names
     *
     * @return JWSSerializerManager
     */
    public function create(array $names): JWSSerializerManager
    {
        $serializers = [];
        foreach ($names as $name) {
            if (!array_key_exists($name, $this->serializers)) {
                throw new \InvalidArgumentException(sprintf('Unsupported serialiser "%s".', $name));
            }
            $serializers[] = $this->serializers[$name];
        }

        return JWSSerializerManager::create($serializers);
    }

    /**
     * @return string[]
     */
    public function names(): array
    {
        return array_keys($this->serializers);
    }

    /**
     * @return JWSSerializerInterface[]
     */
    public function all(): array
    {
        return $this->serializers;
    }

    /**
     * @param JWSSerializerInterface $serializer
     *
     * @return JWSSerializerManagerFactory
     */
    public function add(JWSSerializerInterface $serializer): JWSSerializerManagerFactory
    {
        $this->serializers[$serializer->name()] = $serializer;

        return $this;
    }
}
