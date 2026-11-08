<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure\Stub;

use JsonSerializable;
use Override;
use function strtolower;

/**
 * A pure enum serialized as the lowercase name of its case.
 */
enum AssuranceLevel implements JsonSerializable
{
    case High;

    #[Override]
    public function jsonSerialize(): string
    {
        return strtolower($this->name);
    }
}
