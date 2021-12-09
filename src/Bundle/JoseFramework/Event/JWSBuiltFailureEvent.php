<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class JWSBuiltFailureEvent extends Event
{
    /**
     * @var array
     */
    protected $signatures = [];

    public function __construct(
        protected ?string $payload,
        array $signatures,
        protected bool $isPayloadDetached,
        protected ?bool $isPayloadEncoded,
        private Throwable $throwable
    ) {
        $this->signatures = $signatures;
    }

    public function getPayload(): ?string
    {
        return $this->payload;
    }

    public function isPayloadDetached(): bool
    {
        return $this->isPayloadDetached;
    }

    public function getSignatures(): array
    {
        return $this->signatures;
    }

    public function getisPayloadEncoded(): ?bool
    {
        return $this->isPayloadEncoded;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
