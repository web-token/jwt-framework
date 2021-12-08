<?php

declare(strict_types=1);

namespace Jose\Easy;

use function count;
use Exception;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

class Validate extends AbstractLoader
{
    public static function token(string $token): self
    {
        return new self($token);
    }

    public function run(): JWT
    {
        if (count($this->allowedAlgorithms) !== 0) {
            $this->headerCheckers[] = new AlgorithmChecker($this->allowedAlgorithms, true);
        }
        $jws = (new CompactSerializer())->unserialize($this->token);
        $headerChecker = new HeaderCheckerManager($this->headerCheckers, [new JWSTokenSupport()]);
        $headerChecker->check($jws, 0);

        $verifier = new JWSVerifier(new AlgorithmManager($this->algorithms));
        if (! $verifier->verifyWithKeySet($jws, $this->jwkset, 0)) {
            throw new Exception('Invalid signature');
        }

        $jwt = new JWT();
        $jwt->header->replace($jws->getSignature(0)->getProtectedHeader());
        $jwt->claims->replace(JsonConverter::decode($jws->getPayload()));

        $claimChecker = new ClaimCheckerManager($this->claimCheckers);
        $claimChecker->check($jwt->claims->all(), $this->mandatoryClaims);

        return $jwt;
    }

    protected function getAlgorithmMap(): array
    {
        return [
            HS256::class,
            HS384::class,
            HS512::class,
            RS256::class,
            RS384::class,
            RS512::class,
            PS256::class,
            PS384::class,
            PS512::class,
            ES256::class,
            ES384::class,
            ES512::class,
            EdDSA::class,
        ];
    }
}
