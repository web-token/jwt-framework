<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure\Stub;

/**
 * A pure enum, which the payload encoder cannot serialize.
 */
enum Status
{
    case Active;
}
