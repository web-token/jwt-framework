<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\NestedToken\NestedTokenLoader as BaseNestedTokenLoader;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class NestedTokenLoader extends BaseNestedTokenLoader
{
    public function __construct(
        JWELoader $jweLoader,
        JWSLoader $jwsLoader,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($jweLoader, $jwsLoader);
    }

    public function load(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet, ?int &$signature = null): JWS
    {
        try {
            $jws = parent::load($token, $encryptionKeySet, $signatureKeySet, $signature);
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
