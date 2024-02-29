<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker\Stub;

use Jose\Component\Core\JWT;
use Override;

class OtherToken implements JWT
{
    public function __construct(
        private readonly ?string $payload,
        private readonly array $protectedHeader,
        private readonly array $unprotectedHeader
    ) {
    }

    #[Override]
    public function getPayload(): ?string
    {
        return $this->payload;
    }

    public function getProtectedHeader(): array
    {
        return $this->protectedHeader;
    }

    public function getUnprotectedHeader(): array
    {
        return $this->unprotectedHeader;
    }
}
