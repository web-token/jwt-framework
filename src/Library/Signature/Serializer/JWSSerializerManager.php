<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Serializer;

use InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\UnsupportedSerializerException;
use Jose\Component\Signature\JWS;
use function func_num_args;
use function sprintf;
use function trigger_deprecation;

/**
 * The set of serializers is fixed at construction time: a manager shared as a service cannot be silently extended by
 * one of its consumers.
 */
final readonly class JWSSerializerManager
{
    /**
     * @var JWSSerializer[]
     */
    private array $serializers;

    /**
     * @param JWSSerializer[] $serializers
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
     * @return string[]
     */
    public function list(): array
    {
        return array_keys($this->serializers);
    }

    /**
     * Converts a JWS into a string.
     */
    public function serialize(string $name, JWS $jws, ?int $signatureIndex = null): string
    {
        if (! isset($this->serializers[$name])) {
            throw new UnsupportedSerializerException(sprintf('Unsupported serializer "%s".', $name));
        }

        return $this->serializers[$name]->serialize($jws, $signatureIndex);
    }

    /**
     * Loads data and return a JWS object.
     *
     * When no serializer is able to convert the input, the exception thrown by the last one is chained as the previous
     * exception, so that the actual reason of the failure remains available to the caller.
     *
     * @param string $input A string that represents a JWS
     * @param string|null $name the name of the serializer if the input is unserialized. Passing that argument is
     *                          deprecated since 4.3.0 and it will be removed in 5.0.0: use "unserializeToken()"
     *                          instead.
     *
     * @param-out string $name
     */
    public function unserialize(string $input, ?string &$name = null): JWS
    {
        if (func_num_args() >= 2) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Passing the "$name" argument to "%s::unserialize()" is deprecated and the argument will be removed in 5.0.0. Please use "%s::unserializeToken()" instead: it returns a "%s" object that carries the name of the serializer instead of writing it into a variable of the caller.',
                self::class,
                self::class,
                UnserializationResult::class
            );
        }
        $result = $this->unserializeToken($input);
        $name = $result->getSerializerName();

        return $result->getJws();
    }

    /**
     * Loads data and returns the JWS object it represents, together with the name of the serializer that was able to
     * convert it.
     *
     * When no serializer is able to convert the input, the exception thrown by the last one is chained as the previous
     * exception, so that the actual reason of the failure remains available to the caller.
     *
     * @param string $input A string that represents a JWS
     */
    public function unserializeToken(string $input): UnserializationResult
    {
        $lastError = null;
        foreach ($this->serializers as $serializer) {
            try {
                return new UnserializationResult($serializer->unserialize($input), $serializer->name());
            } catch (InvalidArgumentException $invalidArgumentException) {
                $lastError = $invalidArgumentException;

                continue;
            }
        }

        throw new InvalidSerializationException('Unsupported input.', 0, $lastError);
    }
}
