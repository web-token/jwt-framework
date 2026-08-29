<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when an elliptic curve is not supported by this library or by the current platform.
 */
class UnsupportedCurveException extends InvalidArgumentException
{
}
