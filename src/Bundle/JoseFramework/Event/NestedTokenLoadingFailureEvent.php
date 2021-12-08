<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Symfony\Contracts\EventDispatcher\Event;
use Throwable;

final class NestedTokenLoadingFailureEvent extends Event
{
    public function __construct(
        private string $token,
        private JWKSet $signatureKeySet,
        private JWKSet $encryptionKeySet,
        private Throwable $throwable
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
