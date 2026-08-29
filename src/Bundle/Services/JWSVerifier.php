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
use Jose\Component\Signature\VerificationResult;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * @deprecated since 4.3.0, use EventDispatchingJWSVerifier instead. The class extends a service of
 * the library that will be final in 5.0.0.
 */
final class JWSVerifier extends BaseJWSVerifier
{
    public function __construct(
        AlgorithmManager $signatureAlgorithmManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($signatureAlgorithmManager);
    }

    /**
     * The deprecated methods of the parent class are implemented on top of this one: the events are dispatched
     * whichever method the application calls.
     *
     * @param (callable(Throwable): void)|null $onError
     */
    #[Override]
    public function verify(
        JWS $jws,
        JWK|JWKSet $keys,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?callable $onError = null
    ): VerificationResult {
        $result = parent::verify($jws, $keys, $signatureIndex, $detachedPayload, $onError);
        $jwkset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        $jwk = $result->getKey();
        if ($jwk !== null) {
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

        return $result;
    }
}
