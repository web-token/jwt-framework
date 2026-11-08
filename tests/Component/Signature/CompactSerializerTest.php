<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function chr;
use function explode;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use function sprintf;
use function str_repeat;
use function str_replace;

/**
 * @internal
 */
final class CompactSerializerTest extends TestCase
{
    #[Test]
    public function aTokenWithTooManySegmentsIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported input');

        (new CompactSerializer())->unserialize('eyJhbGciOiJub25lIn0...');
    }

    /**
     * A delimiter-heavy token must be rejected without expanding it into one array entry per delimiter. The
     * threshold is deliberately generous: the unbounded split of this input allocates roughly twenty-five times its
     * size, while the bounded one stays proportional to it.
     */
    #[Test]
    public function aDelimiterHeavyTokenIsRejectedWithoutExhaustingMemory(): void
    {
        $token = str_repeat('.', 2_000_000);
        $serializer = new CompactSerializer();
        memory_reset_peak_usage();
        $before = memory_get_usage();

        try {
            $serializer->unserialize($token);
            static::fail('The token should have been rejected.');
        } catch (InvalidArgumentException $e) {
            static::assertSame('Unsupported input', $e->getMessage());
        }

        static::assertLessThan(8_000_000, memory_get_peak_usage() - $before);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7515#appendix-A.1
     */
    #[Test]
    public function aSignatureWithAByteOutsideTheAlphabetIsRejected(): void
    {
        [$header, $payload, $signature] = explode(
            '.',
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        );
        $serializer = new CompactSerializer();
        static::assertSame(1, $serializer->unserialize($header . '.' . $payload . '.' . $signature)->countSignatures());

        $accepted = [];
        for ($byte = 0x80; $byte <= 0xFF; ++$byte) {
            try {
                $serializer->unserialize($header . '.' . $payload . '.' . str_replace('_', chr($byte), $signature));
                $accepted[] = sprintf('0x%02X', $byte);
            } catch (InvalidArgumentException) {
            }
        }

        static::assertSame([], $accepted);
    }
}
