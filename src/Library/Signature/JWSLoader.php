<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Exception;
use InvalidArgumentException;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use SensitiveParameter;
use Throwable;
use function func_get_arg;
use function func_num_args;
use function is_int;
use function sprintf;

/**
 * @see \Jose\Tests\Component\Signature\JWSLoaderTest
 */
class JWSLoader
{
    private readonly ?int $maxSignatures;

    /**
     * A fourth argument sets the maximum number of signatures of a token: a token with more is rejected before any
     * of them is processed. Without it, the number is not limited. That argument is not part of the signature yet (it
     * will be in 5.0.0) and is read with func_num_args()/func_get_arg(3), so that classes extending this one remain
     * compatible.
     */
    public function __construct(
        private readonly JWSSerializerManager $serializerManager,
        private readonly JWSVerifier $jwsVerifier,
        private readonly ?HeaderCheckerManager $headerCheckerManager
    ) {
        $maxSignatures = func_num_args() > 3 ? func_get_arg(3) : null;
        if ($maxSignatures !== null && (! is_int($maxSignatures) || $maxSignatures < 1)) {
            throw new InvalidArgumentException('The maximum number of signatures must be a positive integer.');
        }
        $this->maxSignatures = $maxSignatures;
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
    public function loadAndVerifyWithKey(
        #[SensitiveParameter]
        string $token,
        JWK $key,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
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
        #[SensitiveParameter]
        string $token,
        JWKSet $keyset,
        ?int &$signature,
        ?string $payload = null
    ): JWS {
        $lastError = null;
        try {
            $jws = $this->serializerManager->unserialize($token);
            $nbSignatures = $jws->countSignatures();
            if ($this->maxSignatures !== null && $nbSignatures > $this->maxSignatures) {
                throw new InvalidArgumentException(sprintf(
                    'The token has too many signatures. The maximum allowed number is %d.',
                    $this->maxSignatures
                ));
            }
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
