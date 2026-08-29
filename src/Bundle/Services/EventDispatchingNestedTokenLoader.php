<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\NestedTokenLoadingSuccessEvent;
use Jose\Component\Core\JWKSet;
use Jose\Component\NestedToken\NestedTokenLoaderInterface;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\LoadingResult;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use function func_num_args;
use function trigger_deprecation;

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
    public function loadAndVerify(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet): LoadingResult
    {
        try {
            $result = $this->loader->loadAndVerify($token, $encryptionKeySet, $signatureKeySet);
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

    /**
     * @param-out int $signature
     */
    #[Override]
    public function load(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet, ?int &$signature = null): JWS
    {
        if (func_num_args() >= 4) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Passing the "$signature" argument to "%s::load()" is deprecated and the argument will be removed in 5.0.0. Please use "%s::loadAndVerify()" instead: it returns a "%s" object that carries the index of the verified signature instead of writing it into a variable of the caller.',
                self::class,
                self::class,
                LoadingResult::class
            );
        }
        $result = $this->loadAndVerify($token, $encryptionKeySet, $signatureKeySet);
        $signature = $result->getSignatureIndex();

        return $result->getJws();
    }
}
