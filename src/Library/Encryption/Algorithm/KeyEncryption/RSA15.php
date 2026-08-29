<?php

declare(strict_types=1);

namespace Jose\Component\Encryption\Algorithm\KeyEncryption;

use Jose\Rsa15\KeyEncryption\RSA15 as Rsa15KeyEncryption;
use function trigger_deprecation;

/**
 * @deprecated since 4.3.0, will be removed in 5.0.0. The RSA1_5 algorithm moved to the "web-token/jwt-rsa15"
 *             package: use Jose\Rsa15\KeyEncryption\RSA15 instead.
 */
final readonly class RSA15 extends Rsa15KeyEncryption
{
    public function __construct()
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The class "%s" is deprecated and will be removed in 5.0.0. The "RSA1_5" algorithm is now shipped by the "web-token/jwt-rsa15" package: require it and use "%s" instead.',
            self::class,
            Rsa15KeyEncryption::class
        );
    }
}
