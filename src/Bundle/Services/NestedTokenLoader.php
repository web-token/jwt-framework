<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWELoaderInterface;
use Jose\Component\NestedToken\NestedTokenLoader as BaseNestedTokenLoader;
use Jose\Component\Signature\JWSLoaderInterface;
use Jose\Component\Signature\LoadingResult;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * @deprecated since 4.3.0, use EventDispatchingNestedTokenLoader instead. The class extends a service of
 * the library that will be final in 5.0.0.
 */
final class NestedTokenLoader extends BaseNestedTokenLoader
{
    public function __construct(
        JWELoaderInterface $jweLoader,
        JWSLoaderInterface $jwsLoader,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($jweLoader, $jwsLoader);
    }

    /**
     * The "load()" method of the parent class is implemented on top of this one: the events are dispatched whichever
     * method the application calls.
     */
    #[Override]
    public function loadAndVerify(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet): LoadingResult
    {
        try {
            $result = parent::loadAndVerify($token, $encryptionKeySet, $signatureKeySet);
            $this->eventDispatcher->dispatch(new NestedTokenLoadingSuccessEvent(
                $token,
                $result->getJws(),
                $signatureKeySet,
                $encryptionKeySet,
                $result->getSignatureIndex()
            ));

            return $result;
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
