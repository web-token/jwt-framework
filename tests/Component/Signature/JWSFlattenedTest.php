<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use PHPUnit\Framework\Attributes\Test;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class JWSFlattenedTest extends SignatureTestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    #[Test]
    public function loadFlattenedJWS(): void
    {
        $loaded = $this->getJWSSerializerManager()
            ->unserialize(
                '{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}'
            );

        static::assertSame('ES256', $loaded->getSignature(0)->getProtectedHeaderParameter('alg'));
        static::assertSame([
            'iss' => 'joe',
            'exp' => 1_300_819_380,
            'http://example.com/is_root' => true,
        ], json_decode((string) $loaded->getPayload(), true, 512, JSON_THROW_ON_ERROR));
    }
}
