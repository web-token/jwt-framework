<?php

declare(strict_types=1);

namespace Jose\Tests\Component\NestedToken;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Encryption\JWELoaderFactory;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\NestedToken\NestedTokenLoaderFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class NestedTokenLoaderFactoryTest extends TestCase
{
    /**
     * @param array<string> $jweHeaderCheckers
     * @param array<string> $jwsHeaderCheckers
     */
    #[DataProvider('dataHeaderCheckers')]
    #[Test]
    public function headerCheckersAreRefusedWithoutAHeaderCheckerManagerFactory(
        array $jweHeaderCheckers,
        array $jwsHeaderCheckers
    ): void {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Header checkers were requested, but no header checker manager factory is available.'
        );

        self::createFactory()->create(
            ['jwe_compact'],
            ['A256KW', 'A256GCM'],
            $jweHeaderCheckers,
            ['jws_compact'],
            ['HS256'],
            $jwsHeaderCheckers
        );
    }

    /**
     * @return iterable<string, array{array<string>, array<string>}>
     */
    public static function dataHeaderCheckers(): iterable
    {
        yield 'encryption' => [['typ'], []];
        yield 'signature' => [[], ['typ']];
    }

    private static function createFactory(): NestedTokenLoaderFactory
    {
        $algorithmManagerFactory = new AlgorithmManagerFactory([new A256KW(), new A256GCM(), new HS256()]);
        $jweSerializerManagerFactory = new JWESerializerManagerFactory();
        $jweSerializerManagerFactory->add(new JWECompactSerializer());
        $jwsSerializerManagerFactory = new JWSSerializerManagerFactory();
        $jwsSerializerManagerFactory->add(new JWSCompactSerializer());

        return new NestedTokenLoaderFactory(
            new JWELoaderFactory($jweSerializerManagerFactory, new JWEDecrypterFactory($algorithmManagerFactory), null),
            new JWSLoaderFactory($jwsSerializerManagerFactory, new JWSVerifierFactory($algorithmManagerFactory), null)
        );
    }
}
