<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure\Stub;

use JsonSerializable;
use Override;

/**
 * A JsonSerializable that returns itself: the payload encoder then serializes its public properties.
 */
final class SelfSerializing implements JsonSerializable
{
    public string $country = 'DE';

    #[Override]
    public function jsonSerialize(): self
    {
        return $this;
    }
}
