<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use JsonException;
use SensitiveParameter;
use Throwable;
use function func_get_arg;
use function func_num_args;
use function sprintf;
use const JSON_ERROR_DEPTH;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

final readonly class JsonConverter
{
    public static function encode(mixed $payload): string
    {
        try {
            return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (Throwable $throwable) {
            throw new InvalidArgumentException('Invalid content.', $throwable->getCode(), $throwable);
        }
    }

    /**
     * Decodes a JSON document. A second argument, read with func_get_arg(1) until it is part of the signature in 5.0.0,
     * bounds its values: true decodes a document of any number of values, false refuses a document of more than
     * BoundedJsonDecoder::MAX_VALUES values, and without it, or with null, such a document is decoded with a
     * deprecation, as 5.0.0 refuses it by default.
     *
     * The message of an exception names the error of json_decode(), whose exception is chained as a copy: the
     * arguments recorded in its trace include the document. The code is that of the JSON error.
     *
     * @throws JsonBoundExceededException if the document is nested too deeply, or if it holds too many values and the
     *                                    second argument is false
     * @throws InvalidArgumentException if the document is not valid JSON, or if the second argument is not a boolean
     */
    public static function decode(#[SensitiveParameter] string $payload): mixed
    {
        BoundedJsonDecoder::checkDocument($payload, func_num_args() > 1 ? func_get_arg(1) : null, __METHOD__);
        try {
            return json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $throwable) {
            $previous = new JsonException($throwable->getMessage(), $throwable->getCode());
            if ($throwable->getCode() === JSON_ERROR_DEPTH) {
                throw new JsonBoundExceededException(
                    'The JSON document is nested too deeply.',
                    $throwable->getCode(),
                    $previous
                );
            }
            throw new InvalidArgumentException(
                sprintf('The JSON document is not valid: %s.', $throwable->getMessage()),
                $throwable->getCode(),
                $previous
            );
        }
    }
}
