<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Tests;

use Jose\Component\Signature\JWS;

/**
 * @group Functional
 */
class JWSFlattenedTest extends SignatureTest
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     *
     * @test
     */
    public function loadFlattenedJWS()
    {
        $loaded = $this->getJWSSerializerManager()->unserialize('{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}');

        static::assertInstanceOf(JWS::class, $loaded);
        static::assertEquals('ES256', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertEquals(['iss' => 'joe', 'exp' => 1300819380, 'http://example.com/is_root' => true], \json_decode($loaded->getPayload(), true));
    }
}
