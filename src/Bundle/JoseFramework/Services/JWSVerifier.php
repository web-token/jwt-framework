<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSVerificationFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier as BaseJWSVerifier;
use Psr\EventDispatcher\EventDispatcherInterface;

final class JWSVerifier extends BaseJWSVerifier
{
    public function __construct(
        AlgorithmManager $signatureAlgorithmManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($signatureAlgorithmManager);
    }

    public function verifyWithKeySet(
        JWS $jws,
        JWKSet $jwkset,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?JWK &$jwk = null
    ): bool {
        $success = parent::verifyWithKeySet($jws, $jwkset, $signatureIndex, $detachedPayload, $jwk);
        if ($success) {
            $this->eventDispatcher->dispatch(new JWSVerificationSuccessEvent(
                $jws,
                $jwkset,
                $signatureIndex,
                $detachedPayload,
                $jwk
            ));
        } else {
            $this->eventDispatcher->dispatch(new JWSVerificationFailureEvent($jws, $jwkset, $detachedPayload));
        }

        return $success;
    }
}
