<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\Services;

use Psr\EventDispatcher\EventDispatcherInterface;
use function func_get_arg;
use function func_num_args;

final readonly class NestedTokenLoaderFactory
{
    public function __construct(
        private JWELoaderFactory $jweLoaderFactory,
        private JWSLoaderFactory $jwsLoaderFactory,
        private EventDispatcherInterface $eventDispatcher
    ) {
    }

    /**
     * A seventh argument sets what the loader does with a token whose "cty" header parameter is outside the protected
     * header, and is passed to the loader. It is read with func_num_args()/func_get_arg(6) until 5.0.0.
     */
    public function create(
        array $jweSerializers,
        array $encryptionAlgorithms,
        array $jweHeaderCheckers,
        array $jwsSerializers,
        array $signatureAlgorithms,
        array $jwsHeaderCheckers
    ): NestedTokenLoader {
        $jweLoader = $this->jweLoaderFactory->create($jweSerializers, $encryptionAlgorithms, $jweHeaderCheckers);
        $jwsLoader = $this->jwsLoaderFactory->create($jwsSerializers, $signatureAlgorithms, $jwsHeaderCheckers);

        return new NestedTokenLoader(
            $jweLoader,
            $jwsLoader,
            $this->eventDispatcher,
            func_num_args() > 6 ? func_get_arg(6) : null
        );
    }
}
