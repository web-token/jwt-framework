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

use Jose\Component\Signature\JWS;

/**
 * Class JWSSerializationManager.
 */
final class JWSSerializerManager
{
    /**
     * @var JWSSerializerInterface[]
     */
    private $serializers = [];

    /**
     * JWSSerializerManager constructor.
     *
     * @param JWSSerializerInterface[] $serializers
     */
    private function __construct(array $serializers)
    {
        foreach ($serializers as $serializer) {
            $this->add($serializer);
        }
    }

    /**
     * @param JWSSerializerInterface[] $serializers
     *
     * @return JWSSerializerManager
     */
    public static function create(array $serializers): self
    {
        return new self($serializers);
    }

    /**
     * @param JWSSerializerInterface $serializer
     *
     * @return JWSSerializerManager
     */
    private function add(JWSSerializerInterface $serializer): self
    {
        $this->serializers[$serializer->name()] = $serializer;

        return $this;
    }

    /**
     * Converts a JWS into a string.
     *
     * @param string   $name
     * @param JWS      $jws
     * @param int|null $signatureIndex
     *
     * @throws \Exception
     *
     * @return string
     */
    public function serialize(string $name, JWS $jws, ?int $signatureIndex = null): string
    {
        if (!array_key_exists($name, $this->serializers)) {
            throw new \InvalidArgumentException(sprintf('Unsupported serializer "%s".', $name));
        }

        return ($this->serializers[$name])->serialize($jws, $signatureIndex);
    }

    /**
     * Loads data and return a JWS object.
     *
     * @param string      $input A string that represents a JWS
     * @param string|null $name  the name of the serializer if the input is unserialized
     *
     * @throws \Exception
     *
     * @return JWS
     */
    public function unserialize(string $input, ?string &$name = null): JWS
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
