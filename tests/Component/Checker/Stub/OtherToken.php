<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Checker\Stub;

use Jose\Component\Core\JWT;

class OtherToken implements JWT
{
    public function __construct(
        private readonly ?string $payload,
        private readonly array $protectedHeader,
        private readonly array $unprotectedHeader
    ) {
    }

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
