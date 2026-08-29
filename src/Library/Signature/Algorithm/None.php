<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Algorithm;

use Jose\Unsecured\Signature\None as DeprecatedNone;
use function trigger_deprecation;

/**
 * @deprecated since 4.3.0, will be removed in 5.0.0. The "none" algorithm moved to the "web-token/jwt-unsecured"
 *             package: use Jose\Unsecured\Signature\None instead.
 */
final readonly class None extends DeprecatedNone
{
    public function __construct()
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The class "%s" is deprecated and will be removed in 5.0.0. The "none" algorithm is now shipped by the "web-token/jwt-unsecured" package: require it and use "%s" instead.',
            self::class,
            DeprecatedNone::class
        );
    }
}
