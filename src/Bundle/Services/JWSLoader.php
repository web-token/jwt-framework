<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSLoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader as BaseJWSLoader;
use Jose\Component\Signature\JWSVerifierInterface;
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

    #[Override]
    public function loadAndVerifyWithKeySet(
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
        try {
            $jws = parent::loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
            $this->eventDispatcher->dispatch(new JWSLoadingSuccessEvent($token, $jws, $keyset, $signature));

            return $jws;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWSLoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }
}
