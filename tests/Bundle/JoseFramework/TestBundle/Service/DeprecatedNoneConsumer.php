<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Jose\Component\Signature\Algorithm\None;

/**
 * A service autowired with the deprecated "none" class of the library, which the bundle keeps until 5.0.0.
 */
final readonly class DeprecatedNoneConsumer
{
    public function __construct(
        public None $algorithm
    ) {
    }
}
