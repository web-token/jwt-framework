<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

use InvalidArgumentException as SplInvalidArgumentException;

/**
 * Base class for the invalid arguments reported by this library.
 *
 * It extends the SPL class so that the catch blocks written for previous versions keep matching.
 */
class InvalidArgumentException extends SplInvalidArgumentException implements JoseException
{
}
