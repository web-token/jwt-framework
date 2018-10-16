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

namespace Jose\Component\Signature\Serializer;

class JWSSerializerManagerFactory
{
    /**
     * @var JWSSerializer[]
     */
    private $serializers = [];

    /**
     * @param string[] $names
     */
    public function create(array $names): JWSSerializerManager
    {
        $serializers = [];
        foreach ($names as $name) {
            if (!\array_key_exists($name, $this->serializers)) {
                throw new \InvalidArgumentException(\sprintf('Unsupported serialiser "%s".', $name));
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
        return \array_keys($this->serializers);
    }

    /**
     * @return JWSSerializer[]
     */
    public function all(): array
    {
        return $this->serializers;
    }

    /**
     * @return JWSSerializerManagerFactory
     */
    public function add(JWSSerializer $serializer): self
    {
        $this->serializers[$serializer->name()] = $serializer;

        return $this;
    }
}
