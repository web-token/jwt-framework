<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;

/**
 * Receives the nested token services of the configuration through the autowiring aliases registered by the bundle. The
 * container cannot be compiled unless those aliases refer to the classes of the services.
 */
final readonly class NestedTokenServiceConsumer
{
    public function __construct(
        private NestedTokenLoader $nestedTokenLoader1NestedTokenLoader,
        private NestedTokenBuilder $nestedTokenBuilder1NestedTokenBuilder
    ) {
    }

    public function getLoader(): NestedTokenLoader
    {
        return $this->nestedTokenLoader1NestedTokenLoader;
    }

    public function getBuilder(): NestedTokenBuilder
    {
        return $this->nestedTokenBuilder1NestedTokenBuilder;
    }
}
