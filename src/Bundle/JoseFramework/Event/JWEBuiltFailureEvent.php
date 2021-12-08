<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class JWEBuiltFailureEvent extends Event
{
    /**
     * @var array
     */
    private $recipients;

    /**
     * @var array
     */
    private $sharedProtectedHeader;

    /**
     * @var array
     */
    private $sharedHeader;

    public function __construct(
        private ?string $payload,
        array $recipients,
        array $sharedProtectedHeader,
        array $sharedHeader,
        private ?string $aad,
        private Throwable $throwable
    ) {
        $this->recipients = $recipients;
        $this->sharedProtectedHeader = $sharedProtectedHeader;
        $this->sharedHeader = $sharedHeader;
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
