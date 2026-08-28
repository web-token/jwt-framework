<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Serializer;

use InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\UnsupportedSerializerException;
use Jose\Component\Encryption\JWE;
use function sprintf;

/**
 * The set of serializers is fixed at construction time: a manager shared as a service cannot be silently extended by
 * one of its consumers.
 */
final readonly class JWESerializerManager
{
    /**
     * @var JWESerializer[]
     */
    private array $serializers;

    /**
     * @param JWESerializer[] $serializers
     */
    public function __construct(iterable $serializers)
    {
        $indexedSerializers = [];
        foreach ($serializers as $serializer) {
            $indexedSerializers[$serializer->name()] = $serializer;
        }
        $this->serializers = $indexedSerializers;
    }

    /**
     * Return the serializer names supported by the manager.
     *
     * @return string[]
     */
    public function names(): array
    {
        return array_keys($this->serializers);
    }

    /**
     * Converts a JWE into a string. Throws an exception if none of the serializer was able to convert the input.
     */
    public function serialize(string $name, JWE $jws, ?int $recipientIndex = null): string
    {
        if (! isset($this->serializers[$name])) {
            throw new UnsupportedSerializerException(sprintf('Unsupported serializer "%s".', $name));
        }

        return $this->serializers[$name]->serialize($jws, $recipientIndex);
    }

    /**
     * Loads data and return a JWE object. Throws an exception if none of the serializer was able to convert the input.
     *
     * When no serializer is able to convert the input, the exception thrown by the last one is chained as the previous
     * exception, so that the actual reason of the failure remains available to the caller.
     *
     * @param string $input A string that represents a JWE
     * @param string|null $name the name of the serializer if the input is unserialized
     */
    public function unserialize(string $input, ?string &$name = null): JWE
    {
        $lastError = null;
        foreach ($this->serializers as $serializer) {
            try {
                $jws = $serializer->unserialize($input);
                $name = $serializer->name();

                return $jws;
            } catch (InvalidArgumentException $invalidArgumentException) {
                $lastError = $invalidArgumentException;

                continue;
            }
        }

        throw new InvalidSerializationException('Unsupported input.', 0, $lastError);
    }
}
