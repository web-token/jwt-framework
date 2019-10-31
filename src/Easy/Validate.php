<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Easy;

use Jose\Component\Checker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

class Validate extends AbstractLoader
{
    private function __construct(string $token)
    {
        parent::__construct($token);
        $this->algorithms = [
            new Algorithm\HS256(),
            new Algorithm\HS384(),
            new Algorithm\HS512(),
            new Algorithm\RS256(),
            new Algorithm\RS384(),
            new Algorithm\RS512(),
            new Algorithm\PS256(),
            new Algorithm\PS384(),
            new Algorithm\PS512(),
            new Algorithm\ES256(),
            new Algorithm\ES384(),
            new Algorithm\ES512(),
            new Algorithm\EdDSA(),
        ];
    }

    public static function token(string $token): self
    {
        return new self($token);
    }

    public function run(): JWT
    {
        if (0 !== \count($this->allowedAlgorithms)) {
            $this->headerCheckers[] = new Checker\AlgorithmChecker($this->allowedAlgorithms, true);
        }
        $jws = (new CompactSerializer())->unserialize($this->token);
        $headerChecker = new Checker\HeaderCheckerManager($this->headerCheckers, [new JWSTokenSupport()]);
        $headerChecker->check($jws, 0);

        $verifier = new JWSVerifier(new AlgorithmManager($this->algorithms));
        $verifier->verifyWithKeySet($jws, $this->jwkset, 0);

        $jwt = new JWT();
        $jwt->header->replace($jws->getSignature(0)->getProtectedHeader());
        $jwt->claims->replace(JsonConverter::decode($jws->getPayload()));

        $claimChecker = new Checker\ClaimCheckerManager($this->claimCheckers);
        $claimChecker->check($jwt->claims->all());

        return $jwt;
    }
}
