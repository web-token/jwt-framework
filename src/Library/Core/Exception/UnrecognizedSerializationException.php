<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown by a serializer when the input is not in its serialization at all: a compact serialization of another number
 * of parts, or a JSON document that is not one of its JSON serializations. A serializer manager then tells the
 * serializer the input belongs to from the others, and chains the exception of that serializer.
 */
class UnrecognizedSerializationException extends InvalidSerializationException
{
}
