<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Component\Core\JWKSet;
use Jose\Component\NestedToken\NestedTokenLoaderInterface;
use Jose\Component\Signature\JWS;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * Dispatches an event whenever a nested token is loaded, without extending the loader it decorates.
 */
final readonly class EventDispatchingNestedTokenLoader implements NestedTokenLoaderInterface
{
    public function __construct(
        private NestedTokenLoaderInterface $loader,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function load(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet, ?int &$signature = null): JWS
    {
        try {
            $jws = $this->loader->load($token, $encryptionKeySet, $signatureKeySet, $signature);
            $this->eventDispatcher->dispatch(new NestedTokenLoadingSuccessEvent(
                $token,
                $jws,
                $signatureKeySet,
                $encryptionKeySet,
                $signature
            ));

            return $jws;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new NestedTokenLoadingFailureEvent(
                $token,
                $signatureKeySet,
                $encryptionKeySet,
                $throwable
            ));

            throw $throwable;
        }
    }
}
