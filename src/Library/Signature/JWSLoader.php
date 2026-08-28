<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Exception;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Throwable;

/**
 * @see \Jose\Tests\Component\Signature\JWSLoaderTest
 */
class JWSLoader
{
    public function __construct(
        private readonly JWSSerializerManager $serializerManager,
        private readonly JWSVerifier $jwsVerifier,
        private readonly ?HeaderCheckerManager $headerCheckerManager
    ) {
    }

    /**
     * Returns the JWSVerifier associated to the JWSLoader.
     */
    public function getJwsVerifier(): JWSVerifier
    {
        return $this->jwsVerifier;
    }

    /**
     * Returns the Header Checker Manager associated to the JWSLoader.
     */
    public function getHeaderCheckerManager(): ?HeaderCheckerManager
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
     */
    public function loadAndVerifyWithKey(string $token, JWK $key, ?int &$signature, ?string $payload = null): JWS
    {
        $keyset = new JWKSet([$key]);

        return $this->loadAndVerifyWithKeySet($token, $keyset, $signature, $payload);
    }

    /**
     * This method will try to load and verify the token using the given key set. It returns a JWS and will populate the
     * $signature variable in case of success, otherwise an exception is thrown.
     *
     * The failure semantics are unchanged, but the last error met along the way - a serialization failure, a rejected
     * header or a key that could not verify the signature - is chained as the previous exception, so that the reason of
     * the failure remains available to the caller.
     */
    public function loadAndVerifyWithKeySet(
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
        $lastError = null;
        try {
            $jws = $this->serializerManager->unserialize($token);
            $nbSignatures = $jws->countSignatures();
            for ($i = 0; $i < $nbSignatures; ++$i) {
                if ($this->processSignature($jws, $keyset, $i, $payload, $lastError)) {
                    $signature = $i;

                    return $jws;
                }
            }
        } catch (Throwable $throwable) {
            $lastError = $throwable;
        }

        throw new Exception('Unable to load and verify the token.', 0, $lastError);
    }

    private function processSignature(
        JWS $jws,
        JWKSet $keyset,
        int $signature,
        ?string $payload,
        ?Throwable &$lastError
    ): bool {
        try {
            if ($this->headerCheckerManager !== null) {
                $this->headerCheckerManager->check($jws, $signature);
            }
            $jwk = null;

            return $this->jwsVerifier->verifyWithKeySet(
                $jws,
                $keyset,
                $signature,
                $payload,
                $jwk,
                static function (Throwable $throwable) use (&$lastError): void {
                    $lastError = $throwable;
                }
            );
        } catch (Throwable $throwable) {
            $lastError = $throwable;

            return false;
        }
    }
}
