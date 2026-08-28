<?php

declare(strict_types=1);

namespace Jose\Component\Core\Exception;

/**
 * Thrown by the loaders when a token cannot be loaded, verified or decrypted.
 *
 * The failure of the last attempt is available through the previous exception.
 */
class InvalidTokenException extends RuntimeException
{
}
