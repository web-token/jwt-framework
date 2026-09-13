<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Jose\Component\KeyManagement\Analyzer\MLDSAKeyAnalyzer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * @internal
 */
final class MLDSAKeyAnalyzerTest extends TestCase
{
    /**
     * @return iterable<string, array{array<string, mixed>, list<string>}>
     */
    public static function keys(): iterable
    {
        $pub = static fn (int $size): string => Base64UrlSafe::encodeUnpadded(str_repeat("\x01", $size));
        $seed = Base64UrlSafe::encodeUnpadded(str_repeat("\x02", 32));

        yield 'well-formed ML-DSA-44 key pair' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub(1312),
            'priv' => $seed,
        ], []];
        yield 'well-formed ML-DSA-87 public key' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-87',
            'pub' => $pub(2592),
        ], []];
        yield 'another key type' => [[
            'kty' => 'oct',
            'k' => $seed,
        ], []];
        yield 'missing alg' => [[
            'kty' => 'AKP',
            'pub' => $pub(1312),
        ], ['high: Invalid key. The parameter "alg" is required on an AKP key.']];
        yield 'unknown alg' => [[
            'kty' => 'AKP',
            'alg' => 'ML-KEM-768',
            'pub' => $pub(1312),
        ], ['high: Invalid key. The algorithm "ML-KEM-768" is not an ML-DSA algorithm.']];
        yield 'pub of another parameter set' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-65',
            'pub' => $pub(1312),
        ], ['high: Invalid key. The parameter "pub" of an ML-DSA-65 key shall be 1952 bytes.']];
        yield 'missing pub' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
        ], ['high: Invalid key. The parameter "pub" is missing or not a string.']];
        yield 'expanded private key as priv' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub(1312),
            'priv' => Base64UrlSafe::encodeUnpadded(str_repeat("\x02", 2560)),
        ], ['high: Invalid key. The parameter "priv" of an ML-DSA key shall be the 32-byte seed.']];
        yield 'priv not a string' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub(1312),
            'priv' => 1,
        ], ['high: Invalid key. The parameter "priv" shall be a string.']];
        yield 'both wrong' => [[
            'kty' => 'AKP',
            'alg' => 'ML-DSA-44',
            'pub' => $pub(1),
            'priv' => $pub(1),
        ], [
            'high: Invalid key. The parameter "pub" of an ML-DSA-44 key shall be 1312 bytes.',
            'high: Invalid key. The parameter "priv" of an ML-DSA key shall be the 32-byte seed.',
        ]];
    }

    /**
     * @param array<string, mixed> $values
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('keys')]
    public function theStructureOfTheKeyIsChecked(array $values, array $expected): void
    {
        $bag = new MessageBag();
        (new MLDSAKeyAnalyzer())->analyze(new JWK($values), $bag);

        $messages = [];
        foreach ($bag as $message) {
            $messages[] = sprintf('%s: %s', $message->getSeverity(), $message->getMessage());
        }
        static::assertSame($expected, $messages);
    }
}
