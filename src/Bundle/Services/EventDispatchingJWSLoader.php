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
use Jose\Component\Signature\LoadingResult;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use function trigger_deprecation;

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
    public function loadAndVerify(string $token, JWK|JWKSet $keys, ?string $payload = null): LoadingResult
    {
        $keyset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        try {
            $result = $this->loader->loadAndVerify($token, $keys, $payload);
            $this->eventDispatcher->dispatch(
                new JWSLoadingSuccessEvent($token, $result->getJws(), $keyset, $result->getSignatureIndex())
            );

            return $result;
        } catch (Throwable $throwable) {
            $this->eventDispatcher->dispatch(new JWSLoadingFailureEvent($token, $keyset, $throwable));

            throw $throwable;
        }
    }

    /**
     * @param-out int $signature
     *
     * @deprecated since 4.3.0, use "loadAndVerify()" instead. Will be removed in 5.0.0.
     */
    public function loadAndVerifyWithKey(string $token, JWK $key, ?int &$signature, ?string $payload = null): JWS
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::loadAndVerifyWithKey()" is deprecated and will be removed in 5.0.0. Please use "%s::loadAndVerify()" instead: it returns a "%s" object that carries the index of the verified signature instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            LoadingResult::class
        );
        $keyset = new JWKSet([$key]);

        return $this->loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
    }

    /**
     * @param-out int $signature
     *
     * @deprecated since 4.3.0, use "loadAndVerify()" instead. Will be removed in 5.0.0.
     */
    public function loadAndVerifyWithKeySet(
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::loadAndVerifyWithKeySet()" is deprecated and will be removed in 5.0.0. Please use "%s::loadAndVerify()" instead: it returns a "%s" object that carries the index of the verified signature instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            LoadingResult::class
        );
        $result = $this->loadAndVerify($token, $keyset, $payload);
        $signature = $result->getSignatureIndex();

        return $result->getJws();
    }
}
