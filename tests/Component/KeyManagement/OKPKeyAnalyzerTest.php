<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Jose\Component\KeyManagement\Analyzer\OKPKeyAnalyzer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * @internal
 */
final class OKPKeyAnalyzerTest extends TestCase
{
    /**
     * @return iterable<string, array{string, int}>
     */
    public static function curves(): iterable
    {
        yield 'Ed25519' => ['Ed25519', 32];
        yield 'Ed448' => ['Ed448', 57];
        yield 'X25519' => ['X25519', 32];
        yield 'X448' => ['X448', 56];
    }

    #[Test]
    #[DataProvider('curves')]
    public function aWellFormedKeyRaisesNoMessage(string $curve, int $size): void
    {
        $key = self::key($curve, $size, $size);

        static::assertSame([], self::analyze(new OKPKeyAnalyzer(), $key));
        static::assertSame([], self::analyze(new OKPKeyAnalyzer(), $key->toPublic()));
    }

    #[Test]
    public function otherKeyTypesAreIgnored(): void
    {
        $key = new JWK([
            'kty' => 'oct',
            'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        static::assertSame([], self::analyze(new OKPKeyAnalyzer(), $key));
    }

    #[Test]
    public function aMissingCurveIsReported(): void
    {
        $key = new JWK([
            'kty' => 'OKP',
            'x' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);

        static::assertSame(
            ['high: Invalid key. The component "crv" is missing.'],
            self::analyze(new OKPKeyAnalyzer(), $key)
        );
    }

    #[Test]
    public function anUnknownCurveIsReported(): void
    {
        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed512',
            'x' => Base64UrlSafe::encodeUnpadded(random_bytes(32)),
        ]);

        static::assertSame(
            ['high: Invalid key. The curve "Ed512" is not supported.'],
            self::analyze(new OKPKeyAnalyzer(), $key)
        );
    }

    #[Test]
    #[DataProvider('curves')]
    public function componentsOfTheWrongSizeAreReported(string $curve, int $size): void
    {
        $key = self::key($curve, $size + 1, $size - 1);

        static::assertSame([
            sprintf('high: Invalid key. The component "x" size shall be %d bytes.', $size),
            sprintf('high: Invalid key. The component "d" size shall be %d bytes.', $size),
        ], self::analyze(new OKPKeyAnalyzer(), $key));
    }

    #[Test]
    public function aNonStringComponentIsReported(): void
    {
        $key = new JWK([
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => 42,
        ]);

        static::assertSame(
            ['high: Invalid key. The component "x" shall be a string.'],
            self::analyze(new OKPKeyAnalyzer(), $key)
        );
    }

    /**
     * @return iterable<string, array{string, string, list<string>}>
     */
    public static function algorithmsAndCurves(): iterable
    {
        yield 'Ed25519 with Ed25519' => ['Ed25519', 'Ed25519', []];
        yield 'Ed25519 with EdDSA' => ['Ed25519', 'EdDSA', []];
        yield 'Ed448 with Ed448' => ['Ed448', 'Ed448', []];
        yield 'X25519 with ECDH-ES' => ['X25519', 'ECDH-ES', []];
        yield 'X448 with ECDH-ES+A256KW' => ['X448', 'ECDH-ES+A256KW', []];
        yield 'Ed448 with EdDSA' => [
            'Ed448',
            'EdDSA',
            ['high: Invalid key. The algorithm "EdDSA" cannot be used with the curve "Ed448"; use "Ed448".'],
        ];
        yield 'Ed448 with Ed25519' => [
            'Ed448',
            'Ed25519',
            ['high: Invalid key. The algorithm "Ed25519" cannot be used with the curve "Ed448"; use "Ed448".'],
        ];
        yield 'Ed25519 with Ed448' => [
            'Ed25519',
            'Ed448',
            ['high: Invalid key. The algorithm "Ed448" cannot be used with the curve "Ed25519"; use "Ed25519".'],
        ];
        yield 'Ed25519 with ECDH-ES' => [
            'Ed25519',
            'ECDH-ES',
            ['high: Invalid key. The algorithm "ECDH-ES" cannot be used with the curve "Ed25519".'],
        ];
        yield 'X448 with Ed448' => [
            'X448',
            'Ed448',
            ['high: Invalid key. The algorithm "Ed448" cannot be used with the curve "X448".'],
        ];
        yield 'X25519 with EdDSA' => [
            'X25519',
            'EdDSA',
            ['high: Invalid key. The algorithm "EdDSA" cannot be used with the curve "X25519".'],
        ];
    }

    #[Test]
    #[DataProvider('algorithmsAndCurves')]
    public function theAlgorithmMustMatchTheCurve(string $curve, string $algorithm, array $expected): void
    {
        $key = new JWK(self::key($curve, OKPKey::KEY_SIZES[$curve], OKPKey::KEY_SIZES[$curve])->all() + [
            'alg' => $algorithm,
        ]);

        static::assertSame($expected, self::analyze(new OKPKeyAnalyzer(), $key));
    }

    #[Test]
    public function theDeprecatedEdDSAAlgorithmIsReportedWithItsReplacement(): void
    {
        $ed25519 = new JWK(self::key('Ed25519', 32, 32)->all() + [
            'alg' => 'EdDSA',
        ]);
        $ed448 = new JWK(self::key('Ed448', 57, 57)->all() + [
            'alg' => 'EdDSA',
        ]);

        static::assertSame(
            ['medium: The algorithm "EdDSA" is deprecated (RFC 9864). Use the fully-specified "Ed25519" algorithm instead.'],
            self::analyze(new AlgorithmAnalyzer(), $ed25519)
        );
        static::assertSame(
            ['medium: The algorithm "EdDSA" is deprecated (RFC 9864). Use the fully-specified "Ed448" algorithm instead.'],
            self::analyze(new AlgorithmAnalyzer(), $ed448)
        );
        static::assertSame([], self::analyze(new AlgorithmAnalyzer(), new JWK(self::key('Ed25519', 32, 32)->all() + [
            'alg' => 'Ed25519',
        ])));
        static::assertSame(
            ['medium: The parameter "alg" should be added.'],
            self::analyze(new AlgorithmAnalyzer(), self::key('Ed25519', 32, 32))
        );
    }

    /**
     * @return list<string>
     */
    private static function analyze(KeyAnalyzer $analyzer, JWK $key): array
    {
        $bag = new MessageBag();
        $analyzer->analyze($key, $bag);
        $messages = [];
        foreach ($bag as $message) {
            $messages[] = sprintf('%s: %s', $message->getSeverity(), $message->getMessage());
        }

        return $messages;
    }

    private static function key(string $curve, int $xSize, int $dSize): JWK
    {
        return new JWK([
            'kty' => 'OKP',
            'crv' => $curve,
            'x' => Base64UrlSafe::encodeUnpadded(random_bytes($xSize)),
            'd' => Base64UrlSafe::encodeUnpadded(random_bytes($dSize)),
        ]);
    }
}
