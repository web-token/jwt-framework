<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when a JOSE header parameter needed to process a token is missing or has an unexpected value.
 *
 * Header checkers report their own failures with Jose\Component\Checker\InvalidHeaderException.
 */
class InvalidHeaderParameterException extends InvalidArgumentException
{
}
