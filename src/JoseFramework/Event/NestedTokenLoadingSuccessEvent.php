<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Event;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Symfony\Contracts\EventDispatcher\Event;

final class NestedTokenLoadingSuccessEvent extends Event
{
    public function __construct(
        private readonly string $token,
        private readonly JWS $jws,
        private readonly JWKSet $signatureKeySet,
        private readonly JWKSet $encryptionKeySet,
        private readonly int $signature
    ) {
    }

    public function getJws(): JWS
    {
        return $this->jws;
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

    public function getSignature(): int
    {
        return $this->signature;
    }
}
