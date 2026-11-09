<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\Exception\UnrecognizedSerializationException;
use SensitiveParameter;
use function is_bool;
use function preg_replace;
use function sprintf;
use function str_replace;
use function substr_count;
use function trigger_deprecation;
use const JSON_ERROR_DEPTH;

/**
 * Decodes the JSON documents of one token, which together may hold at most MAX_VALUES values. json_decode() only
 * limits the depth: a document of brackets decodes to a hundred times its size, and colliding member names make it
 * quadratic.
 *
 * A document rejected for the values it holds or for its depth is rejected with a JsonBoundExceededException, whose
 * message names the bound; the other errors of json_decode() keep the exception of JsonConverter::decode().
 *
 * @internal
 */
final class BoundedJsonDecoder
{
    public const MAX_VALUES = 4096;

    private int $remainingValues = self::MAX_VALUES;

    private bool $exceededMaxDepth = false;

    /**
     * @throws JsonBoundExceededException if the document is nested too deeply, or if the documents given to this
     *                                    decoder hold more than MAX_VALUES values. The code of the exception is that of
     *                                    the JSON error, 0 for the values.
     * @throws InvalidArgumentException if the document is not valid JSON
     */
    public function decode(#[SensitiveParameter] string $json): mixed
    {
        $this->remainingValues -= self::countValues($json);
        if ($this->remainingValues < 0) {
            throw new JsonBoundExceededException(sprintf(
                'The JSON documents of the token hold more JSON values than the %d that are decoded.',
                self::MAX_VALUES
            ));
        }
        try {
            return JsonConverter::decode($json, true);
        } catch (InvalidArgumentException $exception) {
            if ($exception->getCode() !== JSON_ERROR_DEPTH) {
                throw new InvalidArgumentException(
                    'Unsupported input.',
                    $exception->getCode(),
                    $exception->getPrevious()
                );
            }
            $this->exceededMaxDepth = true;
            throw new JsonBoundExceededException(
                'A JSON document of the token is nested too deeply.',
                $exception->getCode(),
                $exception->getPrevious()
            );
        }
    }

    /**
     * Decodes the JSON serialization of a token. A document that is not valid JSON is not such a serialization: it is
     * rejected with an UnrecognizedSerializationException that keeps the message, the code and the previous exception
     * of the error. A document beyond a bound is rejected as decode() rejects it.
     *
     * @throws JsonBoundExceededException if the document goes beyond a bound
     * @throws UnrecognizedSerializationException if the document is not valid JSON
     */
    public function decodeSerialization(#[SensitiveParameter] string $json): mixed
    {
        try {
            return $this->decode($json);
        } catch (JsonBoundExceededException $exception) {
            throw $exception;
        } catch (InvalidArgumentException $exception) {
            throw new UnrecognizedSerializationException(
                $exception->getMessage(),
                $exception->getCode(),
                $exception->getPrevious()
            );
        }
    }

    /**
     * Whether a document given to this decoder was rejected for its depth.
     */
    public function hasExceededMaxDepth(): bool
    {
        return $this->exceededMaxDepth;
    }

    /**
     * Whether the documents given to this decoder hold more than MAX_VALUES values. The document that went beyond the
     * bound was rejected before it was decoded, and so are the documents given after it.
     */
    public function hasExceededMaxValues(): bool
    {
        return $this->remainingValues < 0;
    }

    /**
     * Applies the second argument of a public method that decodes a JSON document on its own, read with
     * func_get_arg(1) until it is part of the signature in 5.0.0: true decodes a document of any number of values,
     * false refuses a document of more than MAX_VALUES values, and null, or no argument, decodes such a document with
     * a deprecation, as 5.0.0 refuses it by default.
     *
     * @param string $method the method that decodes the document, such as "Jose\Component\Core\JWK::createFromJson"
     *
     * @throws InvalidArgumentException if the argument is neither a boolean nor null
     * @throws JsonBoundExceededException if the argument is false and the document holds more than MAX_VALUES values
     */
    public static function checkDocument(#[SensitiveParameter] string $json, mixed $unbounded, string $method): void
    {
        if ($unbounded !== null && ! is_bool($unbounded)) {
            throw new InvalidArgumentException(sprintf(
                'The second argument of "%s()" must be a boolean: true decodes a document of any number of values, false refuses one of more than %d.',
                $method,
                self::MAX_VALUES
            ));
        }
        if ($unbounded === true || ! self::exceedsMaxValues($json)) {
            return;
        }
        if ($unbounded === false) {
            throw new JsonBoundExceededException(sprintf(
                'The JSON document holds more JSON values than the %d that are decoded.',
                self::MAX_VALUES
            ));
        }
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'Decoding a JSON document of more than %d values is deprecated and "%s()" will refuse it by default in 5.0.0. Pass true as the second argument to keep decoding it, or false to refuse it now.',
            self::MAX_VALUES,
            $method
        );
    }

    /**
     * Whether a JSON document holds more than MAX_VALUES values, counted as decode() counts them.
     */
    public static function exceedsMaxValues(#[SensitiveParameter] string $json): bool
    {
        return self::countValues($json) > self::MAX_VALUES;
    }

    /**
     * Counts the brackets, braces and commas found outside the string literals.
     */
    private static function countValues(#[SensitiveParameter] string $json): int
    {
        $structure = preg_replace('/"[^"]*+"/', '', str_replace(['\\\\', '\\"'], '', $json)) ?? $json;

        return substr_count($structure, '[') + substr_count($structure, '{') + substr_count($structure, ',');
    }
}
