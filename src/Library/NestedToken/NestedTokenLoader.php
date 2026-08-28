<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidPayloadException;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWELoaderInterface;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoaderInterface;
use Jose\Component\Signature\LoadingResult;
use function func_num_args;
use function is_string;
use function trigger_deprecation;

/**
 * @final The class will be final in 5.0.0: implement NestedTokenLoaderInterface and decorate the service instead of
 * extending it.
 */
class NestedTokenLoader implements NestedTokenLoaderInterface
{
    public function __construct(
        private readonly JWELoaderInterface $jweLoader,
        private readonly JWSLoaderInterface $jwsLoader
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, NestedTokenLoaderInterface::class);
    }

    /**
     * This method will try to load, decrypt and verify the token. In case of failure, an exception is thrown, otherwise
     * returns the JWS and populates the $signature variable.
     *
     * @param int|null $signature the index of the verified signature. Passing that argument is deprecated since 4.3.0
     *                            and it will be removed in 5.0.0: use "loadAndVerify()" instead.
     *
     * @param-out int $signature
     */
    public function load(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet, ?int &$signature = null): JWS
    {
        if (func_num_args() >= 4) {
            trigger_deprecation(
                'web-token/jwt-framework',
                '4.3.0',
                'Passing the "$signature" argument to "%s::load()" is deprecated and the argument will be removed in 5.0.0. Please use "%s::loadAndVerify()" instead: it returns a "%s" object that carries the index of the verified signature instead of writing it into a variable of the caller.',
                self::class,
                self::class,
                LoadingResult::class
            );
        }
        $result = $this->loadAndVerify($token, $encryptionKeySet, $signatureKeySet);
        $signature = $result->getSignatureIndex();

        return $result->getJws();
    }

    /**
     * This method will try to load, decrypt and verify the token. In case of failure, an exception is thrown, otherwise
     * the JWS, the index of the verified signature and the key that verified it are carried by the returned result.
     */
    public function loadAndVerify(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet): LoadingResult
    {
        $jweResult = $this->jweLoader->loadAndDecrypt($token, $encryptionKeySet);
        $jwe = $jweResult->getJwe();
        $this->checkContentTypeHeader($jwe, $jweResult->getRecipientIndex());
        $payload = $jwe->getPayload();
        if ($payload === null) {
            throw new InvalidPayloadException('The token has no payload.');
        }

        return $this->jwsLoader->loadAndVerify($payload, $signatureKeySet);
    }

    private function checkContentTypeHeader(JWE $jwe, int $recipient): void
    {
        $cty = match (true) {
            $jwe->hasSharedProtectedHeaderParameter('cty') => $jwe->getSharedProtectedHeaderParameter('cty'),
            $jwe->hasSharedHeaderParameter('cty') => $jwe->getSharedHeaderParameter('cty'),
            $jwe->getRecipient($recipient)
                ->hasHeaderParameter('cty') => $jwe->getRecipient($recipient)
                ->getHeaderParameter('cty'),
            default => throw new InvalidArgumentException('The token is not a nested token.'),
        };
        if (! is_string($cty)) {
            throw new InvalidHeaderParameterException('Invalid "cty" header parameter.');
        }

        if (strcasecmp($cty, 'jwt') !== 0) {
            throw new InvalidArgumentException('The token is not a nested token.');
        }
    }
}
