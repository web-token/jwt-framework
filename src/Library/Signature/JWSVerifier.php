<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeySetException;
use Jose\Component\Core\Exception\InvalidPayloadException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Throwable;
use function func_num_args;
use function is_callable;
use function sprintf;
use function trigger_deprecation;

/**
 * @final The class will be final in 5.0.0: implement JWSVerifierInterface and decorate the service instead of
 * extending it.
 */
class JWSVerifier implements JWSVerifierInterface
{
    public function __construct(
        private readonly AlgorithmManager $signatureAlgorithmManager
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWSVerifierInterface::class);
    }

    /**
     * Returns the algorithm manager associated to the JWSVerifier.
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmManager;
    }

    /**
     * This method will try to verify the JWS object using the given key and for the given signature. It returns true if
     * the signature is verified, otherwise false.
     *
     * @return bool true if the verification of the signature succeeded, else false
     */
    public function verifyWithKey(JWS $jws, JWK $jwk, int $signature, ?string $detachedPayload = null): bool
    {
        return $this->verify($jws, $jwk, $signature, $detachedPayload)
            ->isVerified();
    }

    /**
     * This method will try to verify the JWS object using the given key or key set and for the given signature. The
     * key that verified the signature is carried by the returned result.
     *
     * A key that cannot be used, or that does not verify the signature, does not abort the verification: the next key
     * of the key set is tried and the reason of the failure is otherwise lost. The optional callable is called with
     * every discarded Throwable, so that those failures can be observed.
     *
     * @param JWS $jws A JWS object
     * @param JWK|JWKSet $keys The signature will be verified using that key or the keys in that key set
     * @param int $signatureIndex The index of the signature to verify
     * @param string|null $detachedPayload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param (callable(Throwable): void)|null $onError Called with every failure met while trying the keys
     */
    public function verify(
        JWS $jws,
        JWK|JWKSet $keys,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?callable $onError = null
    ): VerificationResult {
        $jwkset = $keys instanceof JWK ? new JWKSet([$keys]) : $keys;
        if ($jwkset->count() === 0) {
            throw new InvalidKeySetException('There is no key in the key set.');
        }
        if ($jws->countSignatures() === 0) {
            throw new InvalidArgumentException('The JWS does not contain any signature.');
        }
        $this->checkPayload($jws, $detachedPayload);

        return $this->verifySignature($jws, $jwkset, $signatureIndex, $detachedPayload, $onError);
    }

    /**
     * This method will try to verify the JWS object using the given key set and for the given signature. It returns
     * true if the signature is verified, otherwise false.
     *
     * A callable is accepted as an additional argument to observe the failures met while trying the keys. That argument
     * is not part of the signature and is read with func_num_args()/func_get_arg(5), so that the objects decorating
     * this one remain compatible.
     *
     * @param JWS $jws A JWS object
     * @param JWKSet $jwkset The signature will be verified using keys in the key set
     * @param int $signatureIndex The index of the signature to verify
     * @param string|null $detachedPayload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param JWK|null $jwk The key used to verify the signature in case of success
     *
     * @return bool true if the verification of the signature succeeded, else false
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

    /**
     * @param (callable(Throwable): void)|null $onError
     */
    private function verifySignature(
        JWS $jws,
        JWKSet $jwkset,
        int $signatureIndex,
        ?string $detachedPayload = null,
        ?callable $onError = null
    ): VerificationResult {
        $signature = $jws->getSignature($signatureIndex);
        $input = $this->getInputToVerify($jws, $signature, $detachedPayload);
        $algorithm = $this->getAlgorithm($signature);
        foreach ($jwkset->all() as $jwk) {
            try {
                KeyChecker::checkKeyUsage($jwk, 'verification');
                KeyChecker::checkKeyAlgorithm($jwk, $algorithm->name());
                if ($algorithm->verify($jwk, $input, $signature->getSignature()) === true) {
                    return VerificationResult::success($signatureIndex, $jwk);
                }
            } catch (Throwable $throwable) {
                if ($onError !== null) {
                    $onError($throwable);
                }

                continue;
            }
        }

        return VerificationResult::failure($signatureIndex);
    }

    private function getInputToVerify(JWS $jws, Signature $signature, ?string $detachedPayload): string
    {
        $payload = $jws->getPayload();
        $isPayloadEmpty = $payload === null || $payload === '';
        $encodedProtectedHeader = $signature->getEncodedProtectedHeader() ?? '';
        $isPayloadBase64Encoded = ! $signature->hasProtectedHeaderParameter(
            'b64'
        ) || $signature->getProtectedHeaderParameter('b64') === true;
        $encodedPayload = $jws->getEncodedPayload();

        if ($isPayloadBase64Encoded && $encodedPayload !== null) {
            return sprintf('%s.%s', $encodedProtectedHeader, $encodedPayload);
        }

        $callable = $isPayloadBase64Encoded ? static fn (?string $p): string => Base64UrlSafe::encodeUnpadded(
            $p ?? ''
        )
            : static fn (?string $p): string => $p ?? '';

        $payloadToUse = $callable($isPayloadEmpty ? $detachedPayload : $payload);

        return sprintf('%s.%s', $encodedProtectedHeader, $payloadToUse);
    }

    private function checkPayload(JWS $jws, ?string $detachedPayload = null): void
    {
        $isPayloadEmpty = $this->isPayloadEmpty($jws->getPayload());
        if ($detachedPayload !== null && ! $isPayloadEmpty) {
            throw new InvalidPayloadException('A detached payload is set, but the JWS already has a payload.');
        }
        if ($isPayloadEmpty && $detachedPayload === null) {
            throw new InvalidPayloadException('The JWS has a detached payload, but no payload is provided.');
        }
    }

    /**
     * @return MacAlgorithm|SignatureAlgorithm
     */
    private function getAlgorithm(Signature $signature): Algorithm
    {
        $protectedHeader = $signature->getProtectedHeader();
        if (! isset($protectedHeader['alg'])) {
            throw new InvalidHeaderParameterException('No "alg" parameter set in the protected header.');
        }
        $alg = $protectedHeader['alg'];

        $algorithm = $this->signatureAlgorithmManager->get($alg);
        if (! $algorithm instanceof SignatureAlgorithm && ! $algorithm instanceof MacAlgorithm) {
            throw new UnsupportedAlgorithmException(sprintf(
                'The algorithm "%s" is not supported or is not a signature or MAC algorithm.',
                $alg
            ));
        }

        return $algorithm;
    }

    private function isPayloadEmpty(?string $payload): bool
    {
        return $payload === null || $payload === '';
    }
}
