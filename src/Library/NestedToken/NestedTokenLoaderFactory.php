<?php

declare(strict_types=1);

namespace Jose\Component\NestedToken;

use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Signature\JWSLoaderFactory;
use function func_get_arg;
use function func_num_args;

class NestedTokenLoaderFactory
{
    public function __construct(
        private readonly JWELoaderFactory $jweLoaderFactory,
        private readonly JWSLoaderFactory $jwsLoaderFactory
    ) {
    }

    /**
     * A seventh argument sets what the loader does with a token whose "cty" header parameter is outside the protected
     * header, and is passed to the loader: true loads it, false refuses it, null loads it with a deprecation. That
     * argument is not part of the signature yet (it will be in 5.0.0) and is read with func_num_args()/func_get_arg(6),
     * so that classes extending this one remain compatible.
     *
     * @param array<string> $jweSerializers
     * @param array<string> $keyEncryptionAlgorithms
     * @param array<string> $jweHeaderCheckers
     * @param array<string> $jwsSerializers
     * @param array<string> $signatureAlgorithms
     * @param array<string> $jwsHeaderCheckers
     */
    public function create(
        array $jweSerializers,
        array $keyEncryptionAlgorithms,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers
    ): NestedTokenLoader {
        $jweLoader = $this->jweLoaderFactory->create($jweSerializers, $keyEncryptionAlgorithms, $jweHeaderCheckers);
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader($jweLoader, $jwsLoader, func_num_args() > 6 ? func_get_arg(6) : null);
    }
}
