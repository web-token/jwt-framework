<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption;

use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;

class NestedTokenLoader
{
    /**
     * @var JWSLoader
     */
    private $jwsLoader;

    /**
     * @var JWELoader
     */
    private $jweLoader;

    /**
     * NestedToken constructor.
     */
    public function __construct(JWELoader $jweLoader, JWSLoader $jwsLoader)
    {
        $this->jweLoader = $jweLoader;
        $this->jwsLoader = $jwsLoader;
    }

    /**
     * This method will try to load, decrypt and verify the token.
     * In case of failure, an exception is thrown, otherwise returns the JWS and populates the $signature variable.
     *
     *
     * @throws \Exception
     */
    public function load(string $token, JWKSet $encryptionKeySet, JWKSet $signatureKeySet, ?int &$signature = null): JWS
    {
        $recipient = null;
        $jwe = $this->jweLoader->loadAndDecryptWithKeySet($token, $encryptionKeySet, $recipient);
        $this->checkContentTypeHeader($jwe, $recipient);
        if (null === $jwe->getPayload()) {
            throw new \InvalidArgumentException('The token has no payload.');
        }

        return $this->jwsLoader->loadAndVerifyWithKeySet($jwe->getPayload(), $signatureKeySet, $signature);
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function checkContentTypeHeader(JWE $jwe, int $recipient)
    {
        switch (true) {
            case $jwe->hasSharedProtectedHeaderParameter('cty'):
                $cty = $jwe->getSharedProtectedHeaderParameter('cty');
                break;
            case $jwe->hasSharedHeaderParameter('cty'):
                $cty = $jwe->getSharedHeaderParameter('cty');
                break;
            case $jwe->getRecipient($recipient)->hasHeaderParameter('cty'):
                $cty = $jwe->getRecipient($recipient)->getHeaderParameter('cty');
                break;
            default:
                throw new \InvalidArgumentException('The token is not a nested token.');
        }

        if (0 !== \strcasecmp($cty, 'jwt')) {
            throw new \InvalidArgumentException('The token is not a nested token.');
        }
    }
}
