<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when an algorithm is not supported by this library or is not registered in the algorithm manager
 * in use.
 */
class UnsupportedAlgorithmException extends InvalidArgumentException
{
}
