<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Jose\SelectiveDisclosure\SDJWTHolder;
use Psr\Clock\ClockInterface;

final readonly class SDJWTHolderFactory
{
    public function __construct(
        private JWSBuilderFactory $jwsBuilderFactory,
        private ClockInterface $clock
    ) {
    }

    /**
     * Creates an SD-JWT Holder that signs its Key Binding JWTs with the given signature algorithm aliases.
     *
     * @param string[] $signatureAlgorithms
     */
    public function create(array $signatureAlgorithms): SDJWTHolder
    {
        return new SDJWTHolder($this->jwsBuilderFactory->create($signatureAlgorithms), $this->clock);
    }
}
