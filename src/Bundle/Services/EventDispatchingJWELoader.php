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
use Jose\Component\Encryption\LoadingResult;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use function trigger_deprecation;

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
    public function loadAndDecrypt(string $token, JWK|JWKSet $keys): LoadingResult
    {
        $keyset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        try {
            $result = $this->loader->loadAndDecrypt($token, $keys);
            $this->eventDispatcher->dispatch(
                new JWELoadingSuccessEvent($token, $result->getJwe(), $keyset, $result->getRecipientIndex())
            );

            return $result;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWELoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }

    /**
     * @param-out int $recipient
     *
     * @deprecated since 4.3.0, use "loadAndDecrypt()" instead. Will be removed in 5.0.0.
     */
    public function loadAndDecryptWithKey(string $token, JWK $key, ?int &$recipient): JWE
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::loadAndDecryptWithKey()" is deprecated and will be removed in 5.0.0. Please use "%s::loadAndDecrypt()" instead: it returns a "%s" object that carries the index of the decrypted recipient instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            LoadingResult::class
        );
        $keyset = new JWKSet([$key]);

        return $this->loadAndDecryptWithKeySet($token, $keyset, $recipient);
    }

    /**
     * @param-out int $recipient
     *
     * @deprecated since 4.3.0, use "loadAndDecrypt()" instead. Will be removed in 5.0.0.
     */
    public function loadAndDecryptWithKeySet(string $token, JWKSet $keyset, ?int &$recipient): JWE
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::loadAndDecryptWithKeySet()" is deprecated and will be removed in 5.0.0. Please use "%s::loadAndDecrypt()" instead: it returns a "%s" object that carries the index of the decrypted recipient instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            LoadingResult::class
        );
        $result = $this->loadAndDecrypt($token, $keyset);
        $recipient = $result->getRecipientIndex();

        return $result->getJwe();
    }
}
