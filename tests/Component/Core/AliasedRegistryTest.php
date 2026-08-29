<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Core;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\UnsupportedSerializerException;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * The factories of the library share the same "alias => object" registry: they list their aliases the same way and they
 * reject an unknown alias the same way.
 *
 * @internal
 */
final class AliasedRegistryTest extends TestCase
{
    #[Test]
    #[DataProvider('factories')]
    public function theRegisteredAliasesAreListed(
        object $factory,
        string $alias,
        string $label,
        string $exceptionClass
    ): void {
        static::assertSame([$alias], $factory->aliases());
        static::assertSame([$alias], array_keys($factory->all()));
    }

    #[Test]
    #[DataProvider('factories')]
    public function anUnknownAliasIsRejected(
        object $factory,
        string $alias,
        string $label,
        string $exceptionClass
    ): void {
        $this->expectException($exceptionClass);
        $this->expectExceptionMessage(sprintf('The %s with the alias "unknown" is not supported.', $label));

        $factory->create(['unknown']);
    }

    #[Test]
    #[DataProvider('factories')]
    public function theRegisteredObjectsAreSelected(
        object $factory,
        string $alias,
        string $label,
        string $exceptionClass
    ): void {
        $manager = $factory->create([$alias]);

        static::assertNotNull($manager);
    }

    #[Test]
    public function theJwsSerializerFactoryStillSupportsTheDeprecatedNamesMethod(): void
    {
        $factory = new JWSSerializerManagerFactory();
        $factory->add(new JWSCompactSerializer());

        $names = null;
        $deprecations = $this->collectDeprecations(static function () use ($factory, &$names): void {
            $names = $factory->names();
        });

        static::assertSame($factory->aliases(), $names);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Signature\Serializer\JWSSerializerManagerFactory::names()" is deprecated',
            $deprecations[0]
        );
    }

    #[Test]
    public function theJweSerializerFactoryStillSupportsTheDeprecatedNamesMethod(): void
    {
        $factory = new JWESerializerManagerFactory();
        $factory->add(new JWECompactSerializer());

        $names = null;
        $deprecations = $this->collectDeprecations(static function () use ($factory, &$names): void {
            $names = $factory->names();
        });

        static::assertSame($factory->aliases(), $names);
        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            'The method "Jose\Component\Encryption\Serializer\JWESerializerManagerFactory::names()" is deprecated',
            $deprecations[0]
        );
    }

    /**
     * @return iterable<string, array{object, string, string, class-string<InvalidArgumentException>}>
     */
    public static function factories(): iterable
    {
        $algorithms = new AlgorithmManagerFactory([new FooAlgorithm()]);

        yield 'algorithm' => [$algorithms, 'foo', 'algorithm', InvalidArgumentException::class];

        $headerCheckers = new HeaderCheckerManagerFactory();
        $headerCheckers->add('foo', new AlgorithmChecker(['HS256']));

        yield 'header checker' => [$headerCheckers, 'foo', 'header checker', InvalidArgumentException::class];

        $claimCheckers = new ClaimCheckerManagerFactory();
        $claimCheckers->add('foo', new AudienceChecker('bar'));

        yield 'claim checker' => [$claimCheckers, 'foo', 'claim checker', InvalidArgumentException::class];

        $jwsSerializers = new JWSSerializerManagerFactory();
        $jwsSerializer = new JWSCompactSerializer();
        $jwsSerializers->add($jwsSerializer);

        yield 'JWS serializer' => [
            $jwsSerializers,
            $jwsSerializer->name(),
            'JWS serializer',
            UnsupportedSerializerException::class,
        ];

        $jweSerializers = new JWESerializerManagerFactory();
        $jweSerializer = new JWECompactSerializer();
        $jweSerializers->add($jweSerializer);

        yield 'JWE serializer' => [
            $jweSerializers,
            $jweSerializer->name(),
            'JWE serializer',
            UnsupportedSerializerException::class,
        ];
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
