<?php

declare(strict_types=1);

namespace Jose\Component\Core\Util;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\JsonBoundExceededException;
use Jose\Component\Core\Exception\UnrecognizedSerializationException;
use SensitiveParameter;
use function preg_replace;
use function sprintf;
use function str_replace;
use function substr_count;
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
            return JsonConverter::decode($json);
        } catch (InvalidArgumentException $exception) {
            if ($exception->getCode() !== JSON_ERROR_DEPTH) {
                throw $exception;
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
     * Counts the brackets, braces and commas found outside the string literals.
     */
    private static function countValues(#[SensitiveParameter] string $json): int
    {
        $structure = preg_replace('/"[^"]*+"/', '', str_replace(['\\\\', '\\"'], '', $json)) ?? $json;

        return substr_count($structure, '[') + substr_count($structure, '{') + substr_count($structure, ',');
    }
}
