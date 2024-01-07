<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class JWEBuiltFailureEvent extends Event
{
    public function __construct(
        private readonly ?string $payload,
        private readonly array $recipients,
        private readonly array $sharedProtectedHeader,
        private readonly array $sharedHeader,
        private readonly ?string $aad,
        private readonly Throwable $throwable
    ) {
    }

    public function getPayload(): ?string
    {
        return $this->payload;
    }

    public function getRecipients(): array
    {
        return $this->recipients;
    }

    public function getSharedProtectedHeader(): array
    {
        return $this->sharedProtectedHeader;
    }

    public function getSharedHeader(): array
    {
        return $this->sharedHeader;
    }

    public function getAad(): ?string
    {
        return $this->aad;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
