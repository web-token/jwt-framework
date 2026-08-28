<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when a key is missing, malformed, of an unexpected type or cannot be used for the requested
 * operation.
 */
class InvalidKeyException extends InvalidArgumentException
{
}
