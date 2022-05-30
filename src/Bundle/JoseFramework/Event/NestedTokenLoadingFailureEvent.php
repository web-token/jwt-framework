<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class NestedTokenLoadingFailureEvent extends Event
{
    public function __construct(
        private readonly string $token,
        private readonly JWKSet $signatureKeySet,
        private readonly JWKSet $encryptionKeySet,
        private readonly Throwable $throwable
    ) {
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getSignatureKeySet(): JWKSet
    {
        return $this->signatureKeySet;
    }

    public function getEncryptionKeySet(): JWKSet
    {
        return $this->encryptionKeySet;
    }

    public function getThrowable(): Throwable
    {
        return $this->throwable;
    }
}
