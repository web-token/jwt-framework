<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\SelectiveDisclosure\SDJWTVerifier;
use Jose\SelectiveDisclosure\VerifiedSDJWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function array_keys;
use function explode;
use function file_get_contents;
use function hash_file;
use function in_array;
use function ksort;
use function sprintf;
use const SORT_STRING;

/**
 * The negative vectors of Polaris, read from tests/fixtures/polaris-negative-vectors/vectors.json, in the layers a
 * Verifier of RFC 9901 applies: the two controls are accepted, and each of the 15 vectors of the "jose" and "sd-jwt"
 * layers is rejected, for the reason it carries. Each of them is a control with one thing changed, re-signed where
 * the change needs it.
 *
 * The other 19 vectors judge what this library leaves to its caller and are not run: the SD-JWT VC profile, OpenID4VP,
 * the "x5c" chain, the binding of "iss" to the "x5c" leaf and the Token Status List (see the README of the fixtures).
 *
 * The Verifier is configured from the "settings" of the corpus: its time, its tolerance, the audience and the nonce.
 * It accepts ES256 only, and "dc+sd-jwt" as the type of the Issuer-signed JWT. The Issuer key is the JWK of the corpus,
 * or the public key of the leaf of the "x5c" chain, as a caller hands it once it has validated the chain.
 *
 * @internal
 */
final class PolarisNegativeVectorsTest extends SelectiveDisclosureTestCase
{
    private const FILE = __DIR__ . '/../fixtures/polaris-negative-vectors/vectors.json';

    /**
     * The SHA-256 of vectors.json, version 0.3.1, as published.
     */
    private const SHA256 = '57be7019119665bbc1515559090099df8f34a483b1e2b6da0a96396adf897073';

    private const ACCEPTED = ['accept-jwks', 'accept-x5c'];

    /**
     * The vectors to reject, with their layer and the reason each is rejected for: messages of the exception or of
     * the exceptions it chains.
     */
    private const REJECTED = [
        'issuer-crit' => ['jose', [
            'The Issuer-signed JWT cannot be verified.',
            'One or more header parameters are marked as critical, but they are missing or have not been checked: urn:example:never-understood.',
        ]],
        'kb-crit' => ['jose', [
            'The Key Binding JWT cannot be verified.',
            'One or more header parameters are marked as critical, but they are missing or have not been checked: urn:example:never-understood.',
        ]],
        'kb-alg-hs256' => ['jose', [
            'The Key Binding JWT cannot be verified.',
            'Unsupported algorithm.',
        ]],
        'issuer-sig-der' => ['jose', [
            'The Issuer-signed JWT cannot be verified.',
            'Unable to load and verify the token.',
        ]],
        'kb-aud-array' => ['sd-jwt', ['The "aud" claim of the Key Binding JWT must be a string.']],
        'kb-aud-missing' => ['sd-jwt', ['The "aud" claim of the Key Binding JWT must be a string.']],
        'kb-nonce-missing' => ['sd-jwt', ['The "nonce" claim of the Key Binding JWT must be a string.']],
        'kb-typ-jwt' => ['sd-jwt', ['The Key Binding JWT must be of type "kb+jwt".']],
        'kb-alg-none' => ['sd-jwt', ['The Key Binding JWT must be a JWS in compact serialization.']],
        'kb-iat-nan' => ['sd-jwt', ['The payload of the Key Binding JWT must be a JSON object.']],
        'kb-exp-string' => ['sd-jwt', [
            'The Key Binding JWT is not valid.',
            '"exp" must be an integer.',
        ]],
        'digest-twice' => ['sd-jwt', ['The digest "T5zzGTVq4ky-qQhFUEzcBsH2se24pq_prVpGEmZr1xg" appears more than once in the SD-JWT.']],
        'claim-overwrite' => ['sd-jwt', ['The disclosed claim "given_name" already exists.']],
        'disclosure-four-elements' => ['sd-jwt', ['The Disclosure must be a JSON array of two or three elements.']],
        'disclosure-named-sd' => ['sd-jwt', ['The claim name "_sd" cannot be selectively disclosed.']],
    ];

    /**
     * The layers of the vectors that are not run.
     */
    private const NOT_RUN = ['haip-x509', 'openid4vp', 'sd-jwt-vc', 'status-list', 'x5c-issuer'];

    /**
     * The number of vectors of each layer, the controls included.
     */
    private const LAYERS = [
        'control' => 2,
        'haip-x509' => 5,
        'jose' => 4,
        'openid4vp' => 1,
        'sd-jwt' => 11,
        'sd-jwt-vc' => 2,
        'status-list' => 8,
        'x5c-issuer' => 3,
    ];

    private static ?array $corpus = null;

    #[Test]
    public function theVectorsAreTheOnesPublished(): void
    {
        static::assertSame(self::SHA256, hash_file('sha256', self::FILE));
        static::assertSame('0.3.1', self::corpus()['version']);
    }

    #[Test]
    public function everyVectorIsRunOrLeftToTheLayerItBelongsTo(): void
    {
        $layers = [];
        $run = [];
        foreach (self::corpus()['vectors'] as $vector) {
            $layers[$vector['layer']] = ($layers[$vector['layer']] ?? 0) + 1;
            if (in_array($vector['layer'], self::NOT_RUN, true)) {
                continue;
            }
            $run[] = $vector['id'];
            if (in_array($vector['id'], self::ACCEPTED, true)) {
                static::assertSame(['control', 'accept'], [$vector['layer'], $vector['expected']], $vector['id']);
            } else {
                static::assertSame(
                    [self::REJECTED[$vector['id']][0] ?? null, 'reject'],
                    [$vector['layer'], $vector['expected']],
                    $vector['id']
                );
            }
        }
        ksort($layers, SORT_STRING);

        static::assertSame(self::LAYERS, $layers);
        static::assertCount(17, $run);
        static::assertSame(
            self::sorted([...self::ACCEPTED, ...array_keys(self::REJECTED)]),
            self::sorted($run)
        );
    }

    #[Test]
    #[DataProvider('acceptedVectors')]
    public function theControlIsAccepted(string $id): void
    {
        $verified = self::verifyVector($id);

        static::assertSame(self::corpus()['settings']['vct'], $verified->getClaims()['vct']);
        static::assertArrayHasKey('given_name', $verified->getClaims());
    }

    #[Test]
    #[DataProvider('rejectedVectors')]
    public function theVectorIsRejectedForTheReasonItCarries(string $id): void
    {
        foreach (self::REJECTED[$id][1] as $message) {
            static::assertRejected($message, static fn () => self::verifyVector($id));
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptedVectors(): iterable
    {
        foreach (self::ACCEPTED as $id) {
            yield $id => [$id];
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedVectors(): iterable
    {
        foreach (array_keys(self::REJECTED) as $id) {
            yield $id => [$id];
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function corpus(): array
    {
        self::$corpus ??= JsonConverter::decode(file_get_contents(self::FILE));

        return self::$corpus;
    }

    /**
     * Verifies the presentation of the vector. The vector and its Issuer key are looked up first, so that a vector
     * missing from the corpus fails the test instead of passing as a rejection.
     */
    private static function verifyVector(string $id): VerifiedSDJWT
    {
        $vector = null;
        foreach (self::corpus()['vectors'] as $candidate) {
            if ($candidate['id'] === $id) {
                $vector = $candidate;
            }
        }
        static::assertNotNull($vector, sprintf('The vector "%s" is missing.', $id));
        $issuerKeys = self::issuerKeys($vector);
        $settings = self::corpus()['settings'];

        return self::vectorVerifier()->verifyWithKeyBinding(
            $vector['presentation'],
            $issuerKeys,
            $settings['audience'],
            $settings['nonce']
        );
    }

    private static function vectorVerifier(): SDJWTVerifier
    {
        $settings = self::corpus()['settings'];

        return new SDJWTVerifier(
            self::jwsLoader(new HeaderCheckerManager([
                new AlgorithmChecker(['ES256'], true),
                new TypeChecker(['dc+sd-jwt']),
            ], [new JWSTokenSupport()])),
            self::clock($settings['now']),
            self::jwsLoader(
                new HeaderCheckerManager([new AlgorithmChecker(['ES256'], true)], [new JWSTokenSupport()])
            ),
            allowedTimeDrift: $settings['max_skew_seconds']
        );
    }

    /**
     * @param array<string, mixed> $vector
     */
    private static function issuerKeys(array $vector): JWK|JWKSet
    {
        if ($vector['trust'] === 'jwks') {
            return JWKSet::createFromKeyData([
                'keys' => self::corpus()['settings']['issuer_jwks'],
            ]);
        }
        $issuerSignedJwt = explode('~', (string) $vector['presentation'])[0];
        $header = JsonConverter::decode(Base64UrlSafe::decodeNoPadding(explode('.', $issuerSignedJwt)[0]));

        return (new JWKFactory())->fromX5C($header['x5c']);
    }
}
