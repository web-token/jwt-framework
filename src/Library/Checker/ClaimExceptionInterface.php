<?php

declare(strict_types=1);

namespace Jose\Component\Checker;

use Jose\Component\Core\Exception\JoseException;

/**
 * Represents an interface for claim exceptions.
 *
 * This interface extends from the JoseException interface, allowing
 * the claim exceptions to be caught with any other exception of this library.
 */
interface ClaimExceptionInterface extends JoseException
{
}
