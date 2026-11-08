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
use function func_get_arg;
use function func_num_args;
use function is_bool;
use function is_string;
use function trigger_deprecation;

/**
 * @final The class will be final in 5.0.0: implement NestedTokenLoaderInterface and decorate the service instead of
 * extending it.
 */
class NestedTokenLoader implements NestedTokenLoaderInterface
{
    private readonly ?bool $allowUnprotectedContentType;

    /**
     * A JWE carries a nested token when its "cty" header parameter is "JWT". Its authentication tag covers its protected
     * header only, so a "cty" in the shared unprotected header or in the header of a recipient can be added to a token
     * without any key. A third argument sets what happens to a token marked that way: true loads it, false refuses it
     * before its payload is read. Without it, or with null, the token loads, but triggers a deprecation, as 5.0.0
     * refuses it by default. That argument is not part of the signature yet (it will be in 5.0.0) and is read with
     * func_num_args()/func_get_arg(2), so that classes extending this one remain compatible.
     */
    public function __construct(
        private readonly JWELoaderInterface $jweLoader,
        private readonly JWSLoaderInterface $jwsLoader
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, NestedTokenLoaderInterface::class);
        $allowUnprotectedContentType = func_num_args() > 2 ? func_get_arg(2) : null;
        if ($allowUnprotectedContentType !== null && ! is_bool($allowUnprotectedContentType)) {
            throw new InvalidArgumentException(
                'The policy for a "cty" header parameter outside the protected header must be a boolean: true accepts it, false refuses it.'
            );
        }
        $this->allowUnprotectedContentType = $allowUnprotectedContentType;
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
        $result = $this->jwsLoader->loadAndVerify($payload, $signatureKeySet);
        if ($this->allowUnprotectedContentType === null && ! $jwe->hasSharedProtectedHeaderParameter('cty')) {
            trigger_deprecation(
                'web-token/jwt-library',
                '4.3.0',
                'Loading a nested token whose "cty" header parameter is not in the protected header is deprecated and "%s" will refuse such a token by default in 5.0.0, as the unprotected headers of a JWE are not authenticated. Have the issuer set "cty" in the protected header, or pass true as the third argument of the constructor to keep loading these tokens, or false to refuse them. With the bundle, set the "allow_unprotected_content_type" option of the nested token loader.',
                self::class
            );
        }

        return $result;
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

        if ($this->allowUnprotectedContentType === false && ! $jwe->hasSharedProtectedHeaderParameter('cty')) {
            throw new InvalidHeaderParameterException('The "cty" header parameter must be in the protected header.');
        }
    }
}
