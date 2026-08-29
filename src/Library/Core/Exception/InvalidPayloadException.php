<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when a payload is missing, is not encoded as expected or is inconsistent with the header
 * parameters of the token.
 */
class InvalidPayloadException extends InvalidArgumentException
{
}
