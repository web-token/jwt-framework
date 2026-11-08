<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure\Stub;

/**
 * A backed enum, which the payload encoder serializes as its value.
 */
enum Nationality: string
{
    case Germany = 'DE';
}
