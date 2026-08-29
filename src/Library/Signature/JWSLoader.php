<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Throwable;
use function trigger_deprecation;

/**
 * @final The class will be final in 5.0.0: implement JWSLoaderInterface and decorate the service instead of
 * extending it.
 *
 * @see \Jose\Tests\Component\Signature\JWSLoaderTest
 */
class JWSLoader implements JWSLoaderInterface
{
    public function __construct(
        private readonly JWSSerializerManager $serializerManager,
        private readonly JWSVerifierInterface $jwsVerifier,
        private readonly ?HeaderCheckerManagerInterface $headerCheckerManager
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWSLoaderInterface::class);
    }

    /**
     * Returns the JWSVerifier associated to the JWSLoader.
     */
    public function getJwsVerifier(): JWSVerifierInterface
    {
        return $this->jwsVerifier;
    }

    /**
     * Returns the Header Checker Manager associated to the JWSLoader.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManagerInterface
    {
        return $this->headerCheckerManager;
    }

    /**
     * Returns the JWSSerializer associated to the JWSLoader.
     */
    public function getSerializerManager(): JWSSerializerManager
    {
        return $this->serializerManager;
    }

    /**
     * This method will try to load and verify the token using the given key. It returns a JWS and will populate the
     * $signature variable in case of success, otherwise an exception is thrown.
     *
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
     * This method will try to load and verify the token using the given key set. It returns a JWS and will populate the
     * $signature variable in case of success, otherwise an exception is thrown.
     *
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

    /**
     * This method will try to load and verify the token using the given key or key set. The JWS, the index of the
     * verified signature and the key that verified it are carried by the returned result, otherwise an exception is
     * thrown.
     *
     * The failure semantics are unchanged, but the last error met along the way - a serialization failure, a rejected
     * header or a key that could not verify the signature - is chained as the previous exception, so that the reason of
     * the failure remains available to the caller.
     *
     * @param string $token A string that represents a JWS
     * @param JWK|JWKSet $keys The signature will be verified using that key or the keys in that key set
     * @param string|null $payload If not null, the value must be the detached payload encoded in Base64 URL safe
     */
    public function loadAndVerify(string $token, JWK|JWKSet $keys, ?string $payload = null): LoadingResult
    {
        $lastError = null;
        try {
            $jws = $this->serializerManager->unserialize($token);
            $nbSignatures = $jws->countSignatures();
            for ($i = 0; $i < $nbSignatures; ++$i) {
                $result = $this->processSignature($jws, $keys, $i, $payload, $lastError);
                $key = $result?->getKey();
                if ($key !== null) {
                    return new LoadingResult($jws, $i, $key);
                }
            }
        } catch (Throwable $throwable) {
            $lastError = $throwable;
        }

        throw new InvalidTokenException('Unable to load and verify the token.', 0, $lastError);
    }

    private function processSignature(
        JWS $jws,
        JWK|JWKSet $keys,
        int $signature,
        ?string $payload,
        ?Throwable &$lastError
    ): ?VerificationResult {
        try {
            if ($this->headerCheckerManager !== null) {
                $this->headerCheckerManager->check($jws, $signature);
            }

            return $this->jwsVerifier->verify(
                $jws,
                $keys,
                $signature,
                $payload,
                static function (Throwable $throwable) use (&$lastError): void {
                    $lastError = $throwable;
                }
            );
        } catch (Throwable $throwable) {
            $lastError = $throwable;

            return null;
        }
    }
}
