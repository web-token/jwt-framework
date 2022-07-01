<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWELoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader as BaseJWELoader;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

final class JWELoader extends BaseJWELoader
{
    public function __construct(
        JWESerializerManager $serializerManager,
        JWEDecrypter $jweDecrypter,
        ?HeaderCheckerManager $headerCheckerManager,
        private readonly EventDispatcherInterface $eventDispatcher
    ) {
        parent::__construct($serializerManager, $jweDecrypter, $headerCheckerManager);
    }

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
