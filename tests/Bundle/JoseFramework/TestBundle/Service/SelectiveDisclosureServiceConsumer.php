<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Jose\SelectiveDisclosure\SDJWTHolder;
use Jose\SelectiveDisclosure\SDJWTIssuerInterface;
use Jose\SelectiveDisclosure\SDJWTVerifierInterface;

/**
 * Receives the Selective Disclosure services of the configuration through the autowiring aliases registered by the
 * bundle, by class and by interface. The container cannot be compiled unless those aliases refer to the services.
 */
final readonly class SelectiveDisclosureServiceConsumer
{
    public function __construct(
        private SDJWTIssuerInterface $issuer1SdJwtIssuer,
        private SDJWTHolder $holder1SdJwtHolder,
        private SDJWTVerifierInterface $verifier1SdJwtVerifier
    ) {
    }

    public function getIssuer(): SDJWTIssuerInterface
    {
        return $this->issuer1SdJwtIssuer;
    }

    public function getHolder(): SDJWTHolder
    {
        return $this->holder1SdJwtHolder;
    }

    public function getVerifier(): SDJWTVerifierInterface
    {
        return $this->verifier1SdJwtVerifier;
    }
}
