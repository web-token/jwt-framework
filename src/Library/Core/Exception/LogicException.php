<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

use LogicException as SplLogicException;

/**
 * Base class for the API misuses reported by this library.
 *
 * It extends the SPL class so that the catch blocks written for previous versions keep matching.
 */
class LogicException extends SplLogicException implements JoseException
{
}
