<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSLoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSLoader as BaseJWSLoader;
use Jose\Component\Signature\JWSVerifierInterface;
use Jose\Component\Signature\LoadingResult;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * @deprecated since 4.3.0, use EventDispatchingJWSLoader instead. The class extends a service of
 * the library that will be final in 5.0.0.
 */
final class JWSLoader extends BaseJWSLoader
{
    public function __construct(
        JWSSerializerManager $serializerManager,
        JWSVerifierInterface $jwsVerifier,
        ?HeaderCheckerManagerInterface $headerCheckerManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($serializerManager, $jwsVerifier, $headerCheckerManager);
    }

    /**
     * The deprecated methods of the parent class are implemented on top of this one: the events are dispatched
     * whichever method the application calls.
     */
    #[Override]
    public function loadAndVerify(string $token, JWK|JWKSet $keys, ?string $payload = null): LoadingResult
    {
        $keyset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        try {
            $result = parent::loadAndVerify($token, $keys, $payload);
            $this->eventDispatcher->dispatch(
                new JWSLoadingSuccessEvent($token, $result->getJws(), $keyset, $result->getSignatureIndex())
            );

            return $result;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWSLoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }
}
