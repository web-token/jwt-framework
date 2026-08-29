<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when a serializer is requested by a name that is not registered in the serializer manager in use.
 */
class UnsupportedSerializerException extends InvalidArgumentException
{
}
