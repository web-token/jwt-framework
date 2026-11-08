<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_fill;
use function hrtime;
use function implode;
use function min;
use const PHP_INT_MAX;

/**
 * @internal
 */
final class JSONGeneralSerializerTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.8.5
     */
    #[Test]
    public function theSignaturesAreLoadedInTheirOrder(): void
    {
        $input = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"bilbo.baggins@hobbiton.example"},"signature":"MIsjqtVlOpa71KE-Mss8_Nq2YH4FGhiocsqrgi5NvyG53uoimic1tcMdSg-qptrzZc7CG6Svw2Y13TDIqHzTUrL_lR2ZFcryNFiHkSw129EghGpwkpxaTn_THJTCglNbADko1MZBCdwzJxwqZc-1RlpO2HibUYyXSwO97BSe0_evZKdjvvKSgsIqjytKSeAMbhMBdMma622_BG5t4sdbuCHtFjp9iJmkio47AIwqkZV1aIZsv33uPUqBBCXbYoQJwt7mxPftHmNlGoOSMxR_3thmXTCm4US-xiNOyhbm8afKK64jU6_TPtQHiJeQJxz9G3Tx-083B745_AfYOnlC9w"},{"header":{"alg":"ES512","kid":"bilbo.baggins@hobbiton.example"},"signature":"ARcVLnaJJaUWG8fG-8t5BREVAuTY8n8YHjwDO1muhcdCoFZFFjfISu0Cdkn9Ybdlmi54ho0x924DUz8sK7ZXkhc7AFM8ObLfTvNCrqcI3Jkl2U5IX3utNhODH6v7xgy1Qahsn0fyb4zSAkje8bAWz4vIfj5pCMYxxm4fgV3q7ZYhm5eD"},{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}]}';
        $serializer = new JSONGeneralSerializer();

        $jws = $serializer->unserialize($input);

        static::assertSame(3, $jws->countSignatures());
        [$rsa, $ecdsa, $hmac] = $jws->getSignatures();
        static::assertSame('eyJhbGciOiJSUzI1NiJ9', $rsa->getEncodedProtectedHeader());
        static::assertSame([
            'alg' => 'RS256',
        ], $rsa->getProtectedHeader());
        static::assertSame([
            'kid' => 'bilbo.baggins@hobbiton.example',
        ], $rsa->getHeader());
        static::assertNull($ecdsa->getEncodedProtectedHeader());
        static::assertSame([
            'alg' => 'ES512',
            'kid' => 'bilbo.baggins@hobbiton.example',
        ], $ecdsa->getHeader());
        static::assertSame([
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ], $hmac->getProtectedHeader());
        static::assertSame([], $hmac->getHeader());
        static::assertSame(
            's0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0',
            Base64UrlSafe::encodeUnpadded($hmac->getSignature())
        );
        static::assertEquals(JsonConverter::decode($input), JsonConverter::decode($serializer->serialize($jws)));
    }

    #[Test]
    public function aTokenWithAnEmptyListOfSignaturesHasNoSignature(): void
    {
        $jws = (new JSONGeneralSerializer())->unserialize('{"payload":"e30","signatures":[]}');

        static::assertSame(0, $jws->countSignatures());
        static::assertSame('{}', $jws->getPayload());
    }

    /**
     * The sender chooses the number of signatures. Four times as many must take about four times as long to parse,
     * not sixteen times as long as when each signature was appended to a copy of the previous ones.
     */
    #[Test]
    public function theParsingTimeGrowsLinearlyWithTheNumberOfSignatures(): void
    {
        $serializer = new JSONGeneralSerializer();
        $fewSignatures = self::tokenWithEmptySignatures(5_000);
        $manySignatures = self::tokenWithEmptySignatures(20_000);

        $fewSignaturesTime = PHP_INT_MAX;
        $manySignaturesTime = PHP_INT_MAX;
        for ($i = 0; $i < 3; ++$i) {
            $fewSignaturesTime = min($fewSignaturesTime, self::timeToUnserialize($serializer, $fewSignatures, 5_000));
            $manySignaturesTime = min(
                $manySignaturesTime,
                self::timeToUnserialize($serializer, $manySignatures, 20_000)
            );
        }

        static::assertLessThan(8 * $fewSignaturesTime, $manySignaturesTime);
    }

    private static function tokenWithEmptySignatures(int $count): string
    {
        return '{"payload":"e30","signatures":[' . implode(',', array_fill(0, $count, '{"signature":""}')) . ']}';
    }

    private static function timeToUnserialize(JSONGeneralSerializer $serializer, string $token, int $count): int
    {
        $start = hrtime(true);
        $jws = $serializer->unserialize($token);
        $time = hrtime(true) - $start;

        static::assertSame($count, $jws->countSignatures());

        return $time;
    }
}
