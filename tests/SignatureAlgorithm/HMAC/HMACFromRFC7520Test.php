<?php

declare(strict_types=1);

namespace Jose\Tests\SignatureAlgorithm\HMAC;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-4.4
 * @see https://tools.ietf.org/html/rfc7520#section-4.5
 * @see https://tools.ietf.org/html/rfc7520#section-4.6
 * @see https://tools.ietf.org/html/rfc7520#section-4.7
 *
 * @internal
 */
final class HMACFromRFC7520Test extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.4
     */
    #[Test]
    public function hS256(): void
    {
        /**
         * Payload Symmetric Key.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.4.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.4.2
         */
        $header = [
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new HS256()]));
        $jwsVerifier = new JWSVerifier(new AlgorithmManager([new HS256()]));
        $compactSerializer = new CompactSerializer();
        $jsonFlattenedSerializer = new JSONFlattenedSerializer();
        $jsonGeneralSerializer = new JSONGeneralSerializer();
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($key, $header)
            ->build();

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.4.3
         */
        $expected_compact_json = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';
        $expected_flattened_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}]}';

        static::assertSame($expected_compact_json, $compactSerializer->serialize($jws, 0));

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        static::assertEqualsCanonicalizing(
            json_decode($expected_flattened_json, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonFlattenedSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertEqualsCanonicalizing(
            json_decode($expected_json, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonGeneralSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );

        $loaded_compact_json = $compactSerializer->unserialize($expected_compact_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_compact_json, $key, 0));

        $loaded_flattened_json = $jsonFlattenedSerializer->unserialize($expected_flattened_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_flattened_json, $key, 0));

        $loaded_json = $jsonGeneralSerializer->unserialize($expected_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_json, $key, 0));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.5
     */
    #[Test]
    public function hS256WithDetachedPayload(): void
    {
        /**
         * Payload Symmetric Key.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.5.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.5.2
         */
        $header = [
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new HS256()]));
        $jwsVerifier = new JWSVerifier(new AlgorithmManager([new HS256()]));
        $compactSerializer = new CompactSerializer();
        $jsonFlattenedSerializer = new JSONFlattenedSerializer();
        $jsonGeneralSerializer = new JSONGeneralSerializer();
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload, true)
            ->addSignature($key, $header)
            ->build();

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.5.3
         */
        $expected_compact_json = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9..s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';
        $expected_flattened_json = '{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}';
        $expected_json = '{"signatures":[{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}]}';

        static::assertSame($expected_compact_json, $compactSerializer->serialize($jws, 0));

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        static::assertEqualsCanonicalizing(
            json_decode($expected_flattened_json, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonFlattenedSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );

        static::assertEqualsCanonicalizing(
            json_decode($expected_json, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonGeneralSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );

        $loaded_compact_json = $compactSerializer->unserialize($expected_compact_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_compact_json, $key, 0, $payload));

        $loaded_flattened_json = $jsonFlattenedSerializer->unserialize($expected_flattened_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_flattened_json, $key, 0, $payload));

        $loaded_json = $jsonGeneralSerializer->unserialize($expected_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_json, $key, 0, $payload));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.6
     */
    #[Test]
    public function hS256WithUnprotectedHeader(): void
    {
        /**
         * Payload Symmetric Key.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.6.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.6.2
         */
        $protectedHeader = [
            'alg' => 'HS256',
        ];
        $unprotectedHeader = [
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new HS256()]));
        $jwsVerifier = new JWSVerifier(new AlgorithmManager([new HS256()]));
        new CompactSerializer();
        $jsonFlattenedSerializer = new JSONFlattenedSerializer();
        $jsonGeneralSerializer = new JSONGeneralSerializer();
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($key, $protectedHeader, $unprotectedHeader)
            ->build();

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.6.3
         */
        $expected_flattened_json = '{"payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","protected": "eyJhbGciOiJIUzI1NiJ9","header": {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature": "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature":"bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"}]}';

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        static::assertEqualsCanonicalizing(
            json_decode($expected_flattened_json, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonFlattenedSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertEqualsCanonicalizing(
            json_decode($expected_json, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonGeneralSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );

        $loaded_flattened_json = $jsonFlattenedSerializer->unserialize($expected_flattened_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_flattened_json, $key, 0));

        $loaded_json = $jsonGeneralSerializer->unserialize($expected_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_json, $key, 0));
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.7
     */
    #[Test]
    public function hS256WithoutProtectedHeader(): void
    {
        /**
         * Payload Symmetric Key.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.7.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.7.2
         */
        $unprotectedHeader = [
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jwsBuilder = new JWSBuilder(new AlgorithmManager([new HS256()]));
        $jwsVerifier = new JWSVerifier(new AlgorithmManager([new HS256()]));
        $jsonFlattenedSerializer = new JSONFlattenedSerializer();
        $jsonGeneralSerializer = new JSONGeneralSerializer();
        $jws = $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($key, [], $unprotectedHeader)
            ->build();

        /**
         * Header.
         *
         * @see https://tools.ietf.org/html/rfc7520#section-4.7.3
         */
        $expected_flattened_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","header":{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature":"xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"header":{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature":"xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"}]}';

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        static::assertEqualsCanonicalizing(
            json_decode($expected_flattened_json, true),
            json_decode($jsonFlattenedSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );
        static::assertEqualsCanonicalizing(
            json_decode($expected_json, true),
            json_decode($jsonGeneralSerializer->serialize($jws, 0), true, 512, JSON_THROW_ON_ERROR)
        );

        $loaded_flattened_json = $jsonFlattenedSerializer->unserialize($expected_flattened_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_flattened_json, $key, 0));

        $loaded_json = $jsonGeneralSerializer->unserialize($expected_json);
        static::assertTrue($jwsVerifier->verifyWithKey($loaded_json, $key, 0));
    }
}
