<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Bundle\JoseFramework\JoseFrameworkBundle;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManager;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerInterface;
use Jose\Component\Checker\HeaderCheckerManagerInterface;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEBuilderInterface;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWEDecrypterInterface;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\JWELoaderInterface;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenBuilderInterface;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\NestedToken\NestedTokenLoaderInterface;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSBuilderInterface;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSLoaderInterface;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSVerifierInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Yaml\Yaml;
use function array_keys;
use function explode;
use function is_a;
use function iterator_to_array;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * The bundle registers an autowiring alias for every service it creates from the configuration. The nested token
 * sources used to alias their own class - the class of the configuration source - instead of the class of the service
 * they create, so nothing could ever be autowired through those aliases.
 *
 * @internal
 */
final class AutowiringAliasesTest extends TestCase
{
    #[Test]
    #[DataProvider('autowiringAliases')]
    public function theAliasedServiceIsAnInstanceOfTheAliasedType(
        string $type,
        string $serviceId,
        string $class
    ): void {
        static::assertTrue(
            is_a($class, $type, true),
            sprintf('The service "%s" is a "%s" and cannot be autowired as a "%s".', $serviceId, $class, $type)
        );
    }

    #[Test]
    public function theNestedTokenServicesAreAliasedWithTheClassOfTheServiceTheyCreate(): void
    {
        $aliases = iterator_to_array(self::autowiringAliases());

        static::assertArrayHasKey(
            NestedTokenLoader::class . ' $nestedTokenLoader1NestedTokenLoader',
            $aliases
        );
        static::assertArrayHasKey(
            NestedTokenBuilder::class . ' $nestedTokenBuilder1NestedTokenBuilder',
            $aliases
        );
    }

    #[Test]
    #[DataProvider('services')]
    public function theServiceIsAlsoAliasedWithItsInterface(string $class, string $interface): void
    {
        $aliases = array_keys(iterator_to_array(self::autowiringAliases()));

        $arguments = self::argumentsAliasedWith($aliases, $class);
        static::assertNotSame([], $arguments, sprintf('No service is aliased with "%s".', $class));
        static::assertSame($arguments, self::argumentsAliasedWith($aliases, $interface));
    }

    /**
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function services(): iterable
    {
        yield 'JWS builder' => [JWSBuilder::class, JWSBuilderInterface::class];
        yield 'JWS verifier' => [JWSVerifier::class, JWSVerifierInterface::class];
        yield 'JWS loader' => [JWSLoader::class, JWSLoaderInterface::class];
        yield 'JWE builder' => [JWEBuilder::class, JWEBuilderInterface::class];
        yield 'JWE decrypter' => [JWEDecrypter::class, JWEDecrypterInterface::class];
        yield 'JWE loader' => [JWELoader::class, JWELoaderInterface::class];
        yield 'Nested token builder' => [NestedTokenBuilder::class, NestedTokenBuilderInterface::class];
        yield 'Nested token loader' => [NestedTokenLoader::class, NestedTokenLoaderInterface::class];
        yield 'Claim checker manager' => [ClaimCheckerManager::class, ClaimCheckerManagerInterface::class];
        yield 'Header checker manager' => [HeaderCheckerManager::class, HeaderCheckerManagerInterface::class];
    }

    /**
     * @param string[] $aliases
     *
     * @return string[]
     */
    private static function argumentsAliasedWith(array $aliases, string $type): array
    {
        $prefix = $type . ' $';
        $arguments = [];
        foreach ($aliases as $alias) {
            if (str_starts_with($alias, $prefix)) {
                $arguments[] = substr($alias, strlen($prefix));
            }
        }

        return $arguments;
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function autowiringAliases(): iterable
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.debug', false);
        (new JoseFrameworkBundle())->getContainerExtension()
            ->load([Yaml::parseFile(__DIR__ . '/../config/config_test.yml')['jose']], $container);

        foreach ($container->getAliases() as $id => $alias) {
            if (str_starts_with($id, '.') || ! str_contains($id, ' $')) {
                continue;
            }
            $serviceId = (string) $alias;

            yield $id => [
                explode(' $', $id, 2)[0],
                $serviceId,
                $container->findDefinition($serviceId)
                    ->getClass() ?? '',
            ];
        }
    }
}
