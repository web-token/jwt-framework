<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTIssuer;

final readonly class SDJWTIssuerFactory
{
    public function __construct(
        private JWSBuilderFactory $jwsBuilderFactory
    ) {
    }

    /**
     * Creates an SD-JWT Issuer that signs with the given signature algorithm aliases.
     *
     * @param string[] $signatureAlgorithms
     */
    public function create(
        array $signatureAlgorithms,
        string $hashAlgorithm = SDJWT::DEFAULT_HASH_ALGORITHM,
        int $minimumDecoyDigests = 0,
        ?int $maximumDecoyDigests = null
    ): SDJWTIssuer {
        return new SDJWTIssuer(
            $this->jwsBuilderFactory->create($signatureAlgorithms),
            $hashAlgorithm,
            $minimumDecoyDigests,
            $maximumDecoyDigests
        );
    }
}
