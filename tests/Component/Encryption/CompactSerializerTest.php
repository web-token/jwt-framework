<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use InvalidArgumentException;
use Jose\Component\Encryption\Serializer\CompactSerializer;
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

        (new CompactSerializer())->unserialize('eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0.....');
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
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.3
     */
    #[Test]
    public function aTagWithAByteOutsideTheAlphabetIsRejected(): void
    {
        [$header, $encryptedKey, $iv, $ciphertext, $tag] = explode(
            '.',
            'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ'
        );
        $prefix = $header . '.' . $encryptedKey . '.' . $iv . '.' . $ciphertext . '.';
        $serializer = new CompactSerializer();
        static::assertSame(1, $serializer->unserialize($prefix . $tag)->countRecipients());

        $accepted = [];
        for ($byte = 0x80; $byte <= 0xFF; ++$byte) {
            try {
                $serializer->unserialize($prefix . str_replace('_', chr($byte), $tag));
                $accepted[] = sprintf('0x%02X', $byte);
            } catch (InvalidArgumentException) {
            }
        }

        static::assertSame([], $accepted);
    }
}
