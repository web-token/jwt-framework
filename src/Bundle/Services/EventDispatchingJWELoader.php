<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWELoadingFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWELoadingSuccessEvent;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Jose\Component\Encryption\JWELoaderInterface;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;

/**
 * Dispatches an event whenever a JWE is loaded, without extending the loader it decorates.
 */
final readonly class EventDispatchingJWELoader implements JWELoaderInterface
{
    public function __construct(
        private JWELoaderInterface $loader,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getJweDecrypter(): JWEDecrypterInterface
    {
        return $this->loader->getJweDecrypter();
    }

    #[Override]
    public function getHeaderCheckerManager(): ?HeaderCheckerManagerInterface
    {
        return $this->loader->getHeaderCheckerManager();
    }

    #[Override]
    public function getSerializerManager(): JWESerializerManager
    {
        return $this->loader->getSerializerManager();
    }

    #[Override]
    public function loadAndDecryptWithKey(string $token, JWK $key, ?int &$recipient): JWE
    {
        $keyset = new JWKSet([$key]);

        return $this->loadAndDecryptWithKeySet($token, $keyset, $recipient);
    }

    #[Override]
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        try {
            $jwe = $this->loader->loadAndDecryptWithKeySet($token, $keyset, $recipient);
            $this->eventDispatcher->dispatch(new JWELoadingSuccessEvent($token, $jwe, $keyset, $recipient));

            return $jwe;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWELoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }
}
