<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Jose\Experimental\Signature\ES256K;

/**
 * A service autowired with the deprecated experimental "ES256K" class, which the bundle keeps until 5.0.0.
 */
final readonly class DeprecatedES256KConsumer
{
    public function __construct(
        public ES256K $algorithm
    ) {
    }
}
