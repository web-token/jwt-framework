<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional;

use Jose\Bundle\JoseFramework\JoseFrameworkBundle;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Yaml\Yaml;
use function explode;
use function is_a;
use function iterator_to_array;
use function sprintf;
use function str_contains;
use function str_starts_with;

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
