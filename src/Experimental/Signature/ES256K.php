<?php

declare(strict_types=1);

namespace Jose\Experimental\Signature;

use Jose\Component\Signature\Algorithm\ES256K as StandardES256K;
use function trigger_deprecation;

/**
 * @deprecated since 4.3.0, will be removed in 5.0.0. "ES256K" is a standard algorithm (RFC 8812) and moved to the
 *             library: use Jose\Component\Signature\Algorithm\ES256K instead.
 */
final readonly class ES256K extends StandardES256K
{
    public function __construct()
    {
        parent::__construct();
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The class "%s" is deprecated and will be removed in 5.0.0. The "ES256K" algorithm is a standard one and moved to the library: use "%s" instead.',
            self::class,
            StandardES256K::class
        );
    }
}
