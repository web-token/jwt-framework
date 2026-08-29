<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

use RuntimeException as SplRuntimeException;

/**
 * Base class for the runtime failures reported by this library.
 *
 * It extends the SPL class so that the catch blocks written for previous versions keep matching.
 */
class RuntimeException extends SplRuntimeException implements JoseException
{
}
