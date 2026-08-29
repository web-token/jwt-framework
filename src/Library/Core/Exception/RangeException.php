<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

use RangeException as SplRangeException;

/**
 * Base class for the out of range values reported by this library.
 *
 * It extends the SPL class so that the catch blocks written for previous versions keep matching.
 */
class RangeException extends SplRangeException implements JoseException
{
}
