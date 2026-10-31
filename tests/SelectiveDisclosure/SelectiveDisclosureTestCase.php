<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use DateTimeImmutable;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidTokenException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\SDJWT;
use Jose\SelectiveDisclosure\SDJWTHolder;
use Jose\SelectiveDisclosure\SDJWTIssuer;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use Jose\Tests\Component\Checker\Stub\MockClock;
use PHPUnit\Framework\TestCase;
use Throwable;
use function array_is_list;
use function is_array;
use function sprintf;
use const SORT_STRING;

/**
 * Keys, services and helpers shared by the tests of the Selective Disclosure component.
 *
 * The examples of RFC 9901 are read from tests/fixtures/rfc9901/examples.json, produced by the extractor of the same
 * directory. The time of the clock is the "iat" of the Key Binding JWTs of the RFC, so that those tokens are fresh.
 *
 * @internal
 */
abstract class SelectiveDisclosureTestCase extends TestCase
{
    protected const NOW = 1748537244;

    protected const AUDIENCE = 'https://verifier.example.org';

    protected const NONCE = '1234567890';

    private static ?array $examples = null;

    private static ?JWK $holderKey = null;

    /**
     * @return array<string, mixed>
     */
    protected static function example(string $name): array
    {
        self::$examples ??= JsonConverter::decode(file_get_contents(__DIR__ . '/../fixtures/rfc9901/examples.json'));

        return self::$examples[$name];
    }

    /**
     * The public key of RFC 9901 appendix A.5, that verifies every Issuer-signed JWT of the RFC.
     */
    protected static function rfcIssuerKey(): JWK
    {
        return new JWK(self::example('issuer_key'));
    }

    /**
     * The P-256 key of RFC 7515 appendix A.3, used to issue the SD-JWTs of the tests.
     */
    protected static function issuerKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);
    }

    protected static function holderKey(): JWK
    {
        self::$holderKey ??= (new JWKFactory())->ec('P-256');

        return self::$holderKey;
    }

    protected static function clock(int $timestamp = self::NOW): MockClock
    {
        return new MockClock(new DateTimeImmutable('@' . $timestamp));
    }

    protected static function jwsBuilder(): JWSBuilder
    {
        return new JWSBuilder(new AlgorithmManager([new ES256(), new ES384(), new PS256(), new HS256()]));
    }

    protected static function issuer(
        string $hashAlgorithm = 'sha-256',
        int $minimumDecoyDigests = 0,
        ?int $maximumDecoyDigests = null
    ): SDJWTIssuer {
        return new SDJWTIssuer(self::jwsBuilder(), $hashAlgorithm, $minimumDecoyDigests, $maximumDecoyDigests);
    }

    protected static function holder(int $timestamp = self::NOW): SDJWTHolder
    {
        return new SDJWTHolder(self::jwsBuilder(), self::clock($timestamp));
    }

    /**
     * A verifier that accepts the Issuer-signed JWTs typed as in RFC 9901 and checks the time claims of the processed
     * payload.
     *
     * @param list<string> $mandatoryClaims
     * @param list<string>|null $hashAlgorithms
     */
    protected static function verifier(
        int $timestamp = self::NOW,
        array $mandatoryClaims = [],
        ?array $hashAlgorithms = null,
        int $keyBindingMaxAge = 300,
        int $allowedTimeDrift = 0
    ): SDJWTVerifier {
        $clock = self::clock($timestamp);

        return new SDJWTVerifier(
            self::jwsLoader(new HeaderCheckerManager([
                new AlgorithmChecker(['ES256', 'ES384', 'PS256']),
                new TypeChecker(['example+sd-jwt', 'dc+sd-jwt']),
            ], [new JWSTokenSupport()])),
            $clock,
            self::jwsLoader(),
            new ClaimCheckerManager([
                new ExpirationTimeChecker($clock),
                new IssuedAtChecker($clock),
                new NotBeforeChecker($clock),
            ]),
            $mandatoryClaims,
            $hashAlgorithms,
            $keyBindingMaxAge,
            $allowedTimeDrift
        );
    }

    protected static function jwsLoader(?HeaderCheckerManager $headerCheckerManager = null): JWSLoader
    {
        return new JWSLoader(
            new JWSSerializerManager([new CompactSerializer()]),
            new JWSVerifier(new AlgorithmManager([new ES256(), new ES384(), new PS256(), new HS256()])),
            $headerCheckerManager
        );
    }

    /**
     * Signs the given payload as a compact JWS, without any of the checks of the Issuer: this is how the tests craft
     * the SD-JWTs a conforming Issuer would never produce.
     *
     * @param array<string, mixed> $payload
     * @param array<string, mixed> $protectedHeader
     */
    protected static function sign(
        array $payload,
        array $protectedHeader = [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ],
        ?JWK $key = null
    ): string {
        $jws = self::jwsBuilder()
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($key ?? self::issuerKey(), $protectedHeader)
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /**
     * Decodes the payload of the Issuer-signed JWT of the given SD-JWT, without verifying it.
     *
     * @return array<string, mixed>
     */
    protected static function payloadOf(SDJWT $sdJwt): array
    {
        $parts = explode('.', $sdJwt->getIssuerSignedJwt());

        return JsonConverter::decode(Base64UrlSafe::decodeNoPadding($parts[1]));
    }

    /**
     * Turns the "marked_claims" of an example into the claim set of the Issuer: every value marked by the extractor
     * becomes a Disclosable carrying the salt printed by the RFC.
     */
    protected static function markedClaims(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        if (! array_is_list($value) && array_keys($value) === ['_selectively_disclosable']) {
            return new Disclosable(
                self::markedClaims($value['_selectively_disclosable']['value']),
                $value['_selectively_disclosable']['salt']
            );
        }
        $result = [];
        foreach ($value as $name => $member) {
            $result[$name] = self::markedClaims($member);
        }

        return $result;
    }

    /**
     * Sorts the members of every object, recursively, so that two JSON documents that only differ in the order of
     * their object members can be compared strictly.
     */
    protected static function canonical(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        $result = [];
        foreach ($value as $name => $member) {
            $result[$name] = self::canonical($member);
        }
        if (! array_is_list($result)) {
            ksort($result, SORT_STRING);
        }

        return $result;
    }

    /**
     * @param list<string> $disclosures
     * @return list<string>
     */
    protected static function sorted(array $disclosures): array
    {
        sort($disclosures, SORT_STRING);

        return $disclosures;
    }

    /**
     * Asserts that the verification is rejected, and that the given message is the one of the exception or of one of
     * the exceptions it chains.
     *
     * @param callable(): mixed $verification
     */
    protected static function assertRejected(string $expectedMessage, callable $verification): void
    {
        try {
            $verification();
        } catch (InvalidTokenException $exception) {
            $messages = [];
            for ($current = $exception; $current instanceof Throwable; $current = $current->getPrevious()) {
                $messages[] = $current->getMessage();
            }
            static::assertContains(
                $expectedMessage,
                $messages,
                sprintf('None of the messages "%s" is the expected one.', implode('", "', $messages))
            );

            return;
        }
        static::fail('The token has been accepted.');
    }

    /**
     * Builds an SD-JWT from its parts, without any check.
     *
     * @param list<string> $disclosures
     */
    protected static function token(string $issuerSignedJwt, array $disclosures = [], string $keyBindingJwt = ''): string
    {
        $token = $issuerSignedJwt . '~';
        foreach ($disclosures as $disclosure) {
            $token .= $disclosure . '~';
        }

        return $token . $keyBindingJwt;
    }
}
