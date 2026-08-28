<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown when a PHP extension or a Composer package required by an algorithm is not installed.
 */
class MissingDependencyException extends RuntimeException
{
}
