<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSLoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoaderInterface;
use Jose\Component\Signature\JWSVerifierInterface;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * Dispatches an event whenever a JWS is loaded, without extending the loader it decorates.
 */
final readonly class EventDispatchingJWSLoader implements JWSLoaderInterface
{
    public function __construct(
        private JWSLoaderInterface $loader,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getJwsVerifier(): JWSVerifierInterface
    {
        return $this->loader->getJwsVerifier();
    }

    #[Override]
    public function getHeaderCheckerManager(): ?HeaderCheckerManagerInterface
    {
        return $this->loader->getHeaderCheckerManager();
    }

    #[Override]
    public function getSerializerManager(): JWSSerializerManager
    {
        return $this->loader->getSerializerManager();
    }

    #[Override]
    public function loadAndVerifyWithKey(string $token, JWK $key, ?int &$signature, ?string $payload = null): JWS
    {
        $keyset = new JWKSet([$key]);

        return $this->loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
    }

    #[Override]
    public function loadAndVerifyWithKeySet(
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
        try {
            $jws = $this->loader->loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
            $this->eventDispatcher->dispatch(new JWSLoadingSuccessEvent($token, $jws, $keyset, $signature));

            return $jws;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWSLoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }
}
