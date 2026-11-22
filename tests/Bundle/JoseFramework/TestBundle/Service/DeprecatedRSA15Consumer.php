<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\TestBundle\Service;

use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;

/**
 * A service autowired with the deprecated "RSA1_5" class of the library, which the bundle keeps until 5.0.0.
 */
final readonly class DeprecatedRSA15Consumer
{
    public function __construct(
        public RSA15 $algorithm
    ) {
    }
}
