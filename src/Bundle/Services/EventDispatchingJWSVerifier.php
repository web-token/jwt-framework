<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Bundle\JoseFramework\Event\JWSVerificationFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWSVerificationSuccessEvent;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifierInterface;
use Jose\Component\Signature\VerificationResult;
use Override;
use Psr\EventDispatcher\EventDispatcherInterface;
use Throwable;
use function func_get_arg;
use function func_num_args;
use function is_callable;
use function trigger_deprecation;

/**
 * Dispatches an event whenever a signature is verified, without extending the verifier it decorates.
 */
final readonly class EventDispatchingJWSVerifier implements JWSVerifierInterface
{
    public function __construct(
        private JWSVerifierInterface $verifier,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    #[Override]
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->verifier->getSignatureAlgorithmManager();
    }

    /**
     * @param (callable(Throwable): void)|null $onError
     */
    #[Override]
    public function verify(
        JWS $jws,
        JWK|JWKSet $keys,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?callable $onError = null
    ): VerificationResult {
        $result = $this->verifier->verify($jws, $keys, $signatureIndex, $detachedPayload, $onError);
        $jwkset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        $jwk = $result->getKey();
        if ($jwk !== null) {
            $this->eventDispatcher->dispatch(
                new JWSVerificationSuccessEvent($jws, $jwkset, $signatureIndex, $detachedPayload, $jwk)
            );
        } else {
            $this->eventDispatcher->dispatch(new JWSVerificationFailureEvent($jws, $jwkset, $detachedPayload));
        }

        return $result;
    }

    #[Override]
    public function verifyWithKey(JWS $jws, JWK $jwk, int $signature, ?string $detachedPayload = null): bool
    {
        return $this->verify($jws, $jwk, $signature, $detachedPayload)
            ->isVerified();
    }

    /**
     * The callable used by the loaders to observe the keys that were discarded is not part of the signature: it is
     * read with func_num_args()/func_get_arg(5) and forwarded to "verify()", otherwise the reason of a failure would
     * be lost as soon as the verifier is decorated.
     *
     * @param-out JWK|null $jwk
     *
     * @deprecated since 4.3.0, use "verify()" instead. Will be removed in 5.0.0.
     */
    public function verifyWithKeySet(
        JWS $jws,
        JWKSet $jwkset,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?JWK &$jwk = null
    ): bool {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::verifyWithKeySet()" is deprecated and will be removed in 5.0.0. Please use "%s::verify()" instead: it returns a "%s" object that carries the key instead of writing it into a variable of the caller.',
            self::class,
            self::class,
            VerificationResult::class
        );
        $onError = func_num_args() >= 6 ? func_get_arg(5) : null;
        if (! is_callable($onError)) {
            $onError = null;
        }
        $result = $this->verify($jws, $jwkset, $signatureIndex, $detachedPayload, $onError);
        if ($result->isVerified()) {
            $jwk = $result->getKey();
        }

        return $result->isVerified();
    }
}
