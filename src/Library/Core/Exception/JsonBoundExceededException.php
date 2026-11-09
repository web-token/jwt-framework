<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when the JSON documents of a token go beyond the bounds this library decodes: more JSON values than
 * BoundedJsonDecoder::MAX_VALUES, or a document nested more deeply than json_decode() reads. The JSON may be valid: the
 * token is rejected for its size or its depth, not for its syntax.
 */
class JsonBoundExceededException extends InvalidArgumentException
{
}
