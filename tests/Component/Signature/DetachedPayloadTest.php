<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\Exception\InvalidPayloadException;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use PHPUnit\Framework\Attributes\Test;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * A detached payload and a payload that is present but empty are two different tokens.
 *
 * @internal
 */
final class DetachedPayloadTest extends SignatureTestCase
{
    private const CONTENT = '{"amount":10,"to":"alice"}';

    private const OTHER_CONTENT = '{"amount":1000000,"to":"mallory"}';

    #[Test]
    public function aDetachedPayloadIsVerifiedAgainstTheContentProvidedByTheCaller(): void
    {
        $token = $this->getJWSSerializerManager()
            ->serialize('jws_json_flattened', $this->sign(self::CONTENT, true));
        $jws = $this->getJWSSerializerManager()
            ->unserialize($token);

        static::assertArrayNotHasKey('payload', json_decode($token, true, 512, JSON_THROW_ON_ERROR));
        static::assertTrue($this->verify($jws, self::CONTENT));
        static::assertFalse($this->verify($jws, self::OTHER_CONTENT));
    }

    #[Test]
    public function aFlattenedTokenCarryingAnEmptyPayloadMemberRefusesADetachedPayload(): void
    {
        $jws = $this->getJWSSerializerManager()
            ->unserialize($this->rewrapAsFlattened());

        $this->expectException(InvalidPayloadException::class);
        $this->expectExceptionMessage('A detached payload is set, but the JWS already has a payload.');

        $this->verify($jws, self::OTHER_CONTENT);
    }

    #[Test]
    public function aGeneralTokenCarryingAnEmptyPayloadMemberRefusesADetachedPayload(): void
    {
        $jws = $this->getJWSSerializerManager()
            ->unserialize($this->rewrapAsGeneral());

        $this->expectException(InvalidPayloadException::class);
        $this->expectExceptionMessage('A detached payload is set, but the JWS already has a payload.');

        $this->verify($jws, self::OTHER_CONTENT);
    }

    #[Test]
    public function anUnencodedPayloadThatIsPresentButEmptyRefusesADetachedPayload(): void
    {
        $jws = $this->getJWSSerializerManager()
            ->unserialize($this->rewrapAsFlattened([
                'b64' => false,
                'crit' => ['b64'],
            ]));

        $this->expectException(InvalidPayloadException::class);
        $this->expectExceptionMessage('A detached payload is set, but the JWS already has a payload.');

        $this->verify($jws, self::OTHER_CONTENT);
    }

    #[Test]
    public function aCompactTokenWithoutPayloadIsDetached(): void
    {
        $jws = $this->getJWSSerializerManager()
            ->unserialize(
                $this->getJWSSerializerManager()
                    ->serialize('jws_compact', $this->sign(self::CONTENT, true))
            );

        static::assertTrue($jws->isPayloadDetached());
        static::assertTrue($this->verify($jws, self::CONTENT));
        static::assertFalse($this->verify($jws, self::OTHER_CONTENT));
    }

    #[Test]
    public function anEmptyPayloadThatIsNotDetachedSurvivesTheFlattenedRoundTrip(): void
    {
        $token = $this->getJWSSerializerManager()
            ->serialize('jws_json_flattened', $this->sign('', false));
        $jws = $this->getJWSSerializerManager()
            ->unserialize($token);

        static::assertSame('', json_decode($token, true, 512, JSON_THROW_ON_ERROR)['payload']);
        static::assertFalse($jws->isPayloadDetached());
        static::assertTrue($this->verify($jws, null));
    }

    #[Test]
    public function anEmptyPayloadThatIsNotDetachedSurvivesTheGeneralRoundTrip(): void
    {
        $token = $this->getJWSSerializerManager()
            ->serialize('jws_json_general', $this->sign('', false));
        $jws = $this->getJWSSerializerManager()
            ->unserialize($token);

        static::assertSame('', json_decode($token, true, 512, JSON_THROW_ON_ERROR)['payload']);
        static::assertFalse($jws->isPayloadDetached());
        static::assertTrue($this->verify($jws, null));
    }

    #[Test]
    public function aDetachedPayloadSurvivesTheGeneralRoundTrip(): void
    {
        $jws = $this->getJWSSerializerManager()
            ->unserialize(
                $this->getJWSSerializerManager()
                    ->serialize('jws_json_general', $this->sign(self::CONTENT, true))
            );

        static::assertTrue($jws->isPayloadDetached());
        static::assertArrayNotHasKey('payload', json_decode(
            $this->getJWSSerializerManager()
                ->serialize('jws_json_general', $jws),
            true,
            512,
            JSON_THROW_ON_ERROR
        ));
        static::assertTrue($this->verify($jws, self::CONTENT));
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private function rewrapAsFlattened(array $protectedHeader = []): string
    {
        $signed = json_decode(
            $this->getJWSSerializerManager()
                ->serialize('jws_json_flattened', $this->sign('', true, $protectedHeader)),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        return json_encode([
            'payload' => '',
            'protected' => $signed['protected'],
            'signature' => $signed['signature'],
        ], JSON_THROW_ON_ERROR);
    }

    private function rewrapAsGeneral(): string
    {
        $signed = json_decode($this->rewrapAsFlattened(), true, 512, JSON_THROW_ON_ERROR);

        return json_encode([
            'payload' => '',
            'signatures' => [
                [
                    'protected' => $signed['protected'],
                    'signature' => $signed['signature'],
                ],
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private function sign(string $payload, bool $isDetached, array $protectedHeader = []): JWS
    {
        return $this->getJWSBuilderFactory()
            ->create(['HS256'])
            ->create()
            ->withPayload($payload, $isDetached)
            ->addSignature($this->key(), [
                'alg' => 'HS256',
            ] + $protectedHeader)
            ->build();
    }

    private function verify(JWS $jws, ?string $detachedPayload): bool
    {
        return $this->getJWSVerifierFactory()
            ->create(['HS256'])
            ->verifyWithKey($jws, $this->key(), 0, $detachedPayload);
    }

    private function key(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g',
        ]);
    }
}
