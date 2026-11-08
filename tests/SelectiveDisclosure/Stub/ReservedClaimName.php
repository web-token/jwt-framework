<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure\Stub;

use JsonSerializable;
use Override;

/**
 * An enum serialized as an object whose member is the reserved claim name of the case.
 */
enum ReservedClaimName: string implements JsonSerializable
{
    case Digests = '_sd';
    case ArrayElementDigest = '...';
    case HashAlgorithm = '_sd_alg';

    /**
     * @return array<string, string>
     */
    #[Override]
    public function jsonSerialize(): array
    {
        return [
            $this->value => 'value',
        ];
    }
}
