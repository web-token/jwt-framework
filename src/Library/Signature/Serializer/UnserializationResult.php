<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Serializer;

use Jose\Component\Signature\JWS;

/**
 * The result of the conversion of a string into a JWS by the JWSSerializerManager.
 *
 * It replaces the "?string &$name" output parameter of JWSSerializerManager::unserialize(): the name of the
 * serializer that converted the input is carried by the result instead of being written into a variable of the
 * caller.
 */
final readonly class UnserializationResult
{
    public function __construct(
        private JWS $jws,
        private string $serializerName
    ) {
    }

    /**
     * The JWS the input has been converted into.
     */
    public function getJws(): JWS
    {
        return $this->jws;
    }

    /**
     * The name of the serializer that converted the input.
     */
    public function getSerializerName(): string
    {
        return $this->serializerName;
    }
}
