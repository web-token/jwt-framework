<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Serializer;

use Jose\Component\Encryption\JWE;

/**
 * The result of the conversion of a string into a JWE by the JWESerializerManager.
 *
 * It replaces the "?string &$name" output parameter of JWESerializerManager::unserialize(): the name of the
 * serializer that converted the input is carried by the result instead of being written into a variable of the
 * caller.
 */
final readonly class UnserializationResult
{
    public function __construct(
        private JWE $jwe,
        private string $serializerName
    ) {
    }

    /**
     * The JWE the input has been converted into.
     */
    public function getJwe(): JWE
    {
        return $this->jwe;
    }

    /**
     * The name of the serializer that converted the input.
     */
    public function getSerializerName(): string
    {
        return $this->serializerName;
    }
}
