<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWELoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Jose\Component\Encryption\JWELoader as BaseJWELoader;
use Jose\Component\Encryption\LoadingResult;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * @deprecated since 4.3.0, use EventDispatchingJWELoader instead. The class extends a service of
 * the library that will be final in 5.0.0.
 */
final class JWELoader extends BaseJWELoader
{
    public function __construct(
        JWESerializerManager $serializerManager,
        JWEDecrypterInterface $jweDecrypter,
        ?HeaderCheckerManagerInterface $headerCheckerManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($serializerManager, $jweDecrypter, $headerCheckerManager);
    }

    /**
     * The deprecated methods of the parent class are implemented on top of this one: the events are dispatched
     * whichever method the application calls.
     */
    #[Override]
    public function loadAndDecrypt(string $token, JWK|JWKSet $keys): LoadingResult
    {
        $keyset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        try {
            $result = parent::loadAndDecrypt($token, $keys);
            $this->eventDispatcher->dispatch(
                new JWELoadingSuccessEvent($token, $result->getJwe(), $keyset, $result->getRecipientIndex())
            );

            return $result;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWELoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }
}
