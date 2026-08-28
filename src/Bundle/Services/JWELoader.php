<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWELoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Jose\Component\Encryption\JWELoader as BaseJWELoader;
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

    #[Override]
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        try {
            $jwe = parent::loadAndDecryptWithKeySet($token, $keyset, $recipient);
            $this->eventDispatcher->dispatch(new JWELoadingSuccessEvent($token, $jwe, $keyset, $recipient));

            return $jwe;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWELoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }
}
