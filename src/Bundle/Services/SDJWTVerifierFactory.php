<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use Psr\Clock\ClockInterface;

final readonly class SDJWTVerifierFactory
{
    public function __construct(
        private JWSLoaderFactory $jwsLoaderFactory,
        private ClaimCheckerManagerFactory $claimCheckerManagerFactory,
        private ClockInterface $clock
    ) {
    }

    /**
     * Creates an SD-JWT Verifier. The Issuer-signed JWTs are loaded with the signature algorithm and header checker
     * aliases, the Key Binding JWTs with their own aliases, the signature algorithms of the Issuer-signed JWTs when
     * none is given, and the processed payloads are checked with the claim checker aliases.
     *
     * @param string[] $signatureAlgorithms
     * @param string[] $headerCheckers
     * @param string[] $keyBindingSignatureAlgorithms
     * @param string[] $keyBindingHeaderCheckers
     * @param string[] $claimCheckers
     * @param list<string> $mandatoryClaims
     * @param list<string> $hashAlgorithms the IANA names of the accepted hash functions, all the supported ones when
     *                                     empty
     */
    public function create(
        array $signatureAlgorithms,
        array $headerCheckers = [],
        array $keyBindingSignatureAlgorithms = [],
        array $keyBindingHeaderCheckers = [],
        array $claimCheckers = [],
        array $mandatoryClaims = [],
        array $hashAlgorithms = [],
        int $keyBindingMaxAge = 300,
        int $allowedTimeDrift = 0
    ): SDJWTVerifier {
        return new SDJWTVerifier(
            $this->jwsLoaderFactory->create([CompactSerializer::NAME], $signatureAlgorithms, $headerCheckers),
            $this->clock,
            $this->jwsLoaderFactory->create(
                [CompactSerializer::NAME],
                $keyBindingSignatureAlgorithms === [] ? $signatureAlgorithms : $keyBindingSignatureAlgorithms,
                $keyBindingHeaderCheckers
            ),
            $this->claimCheckerManagerFactory->create($claimCheckers),
            $mandatoryClaims,
            $hashAlgorithms === [] ? null : $hashAlgorithms,
            $keyBindingMaxAge,
            $allowedTimeDrift
        );
    }
}
