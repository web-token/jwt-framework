<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class JWEBuiltFailureEvent extends Event
{
    public function __construct(
        private ?string $payload,
        private array $recipients,
        private array $sharedProtectedHeader,
        private array $sharedHeader,
        private ?string $aad,
        private Throwable $throwable
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
