<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSVerificationFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifierInterface;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;

/**
 * Dispatches an event whenever a signature is verified, without extending the verifier it decorates.
 */
final readonly class EventDispatchingJWSVerifier implements JWSVerifierInterface
{
    public function __construct(
        private JWSVerifierInterface $verifier,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->verifier->getSignatureAlgorithmManager();
    }

    #[Override]
    public function verifyWithKey(JWS $jws, JWK $jwk, int $signature, ?string $detachedPayload = null): bool
    {
        $jwkset = new JWKSet([$jwk]);

        return $this->verifyWithKeySet($jws, $jwkset, $signature, $detachedPayload);
    }

    /**
     * The callable used by the loaders to observe the keys that were discarded is not part of the signature yet: it is
     * read with func_num_args()/func_get_arg(5) and forwarded to the decorated verifier, otherwise the reason of a
     * failure would be lost as soon as the verifier is decorated.
     */
    #[Override]
    public function verifyWithKeySet(
        JWS $jws,
        JWKSet $jwkset,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?JWK &$jwk = null
    ): bool {
        $success = func_num_args() >= 6 ? $this->verifier->verifyWithKeySet(
            $jws,
            $jwkset,
            $signatureIndex,
            $detachedPayload,
            $jwk,
            func_get_arg(5)
        ) : $this->verifier->verifyWithKeySet($jws, $jwkset, $signatureIndex, $detachedPayload, $jwk);

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
