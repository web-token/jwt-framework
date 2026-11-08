<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\DependencyInjection\Compiler;

use InvalidArgumentException;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\AlgorithmCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\ClaimCheckerCompilerPass;
use Jose\Bundle\JoseFramework\DependencyInjection\Compiler\HeaderCheckerCompilerPass;
use Jose\Bundle\JoseFramework\Services\ClaimCheckerManagerFactory;
use Jose\Bundle\JoseFramework\Services\HeaderCheckerManagerFactory;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\HS256;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\EventDispatcher\EventDispatcher;
use function sprintf;

/**
 * @internal
 */
final class TaggedServiceAliasesTest extends TestCase
{
    /**
     * @param class-string $factory
     * @param list<mixed> $serviceArguments
     */
    #[DataProvider('dataPasses')]
    #[Test]
    public function anAliasSharedByTwoServicesIsRefused(
        CompilerPassInterface $pass,
        string $factory,
        string $tag,
        string $label,
        string $serviceClass,
        array $serviceArguments
    ): void {
        $container = $this->createContainer($pass, $factory);
        $container->register('app.first', $serviceClass)
            ->setArguments($serviceArguments)
            ->setPublic(true)
            ->addTag($tag, [
                'alias' => 'shared',
            ]);
        $container->register('app.second', $serviceClass)
            ->setArguments($serviceArguments)
            ->setPublic(true)
            ->addTag($tag, [
                'alias' => 'shared',
            ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The services "app.first" and "app.second" are both tagged "%s" with the alias "shared", but an alias names a single service. Give each service an alias of its own.',
            $tag
        ));

        $container->compile(true);
    }

    /**
     * @param class-string $factory
     * @param list<mixed> $serviceArguments
     */
    #[DataProvider('dataPasses')]
    #[Test]
    public function aServiceTaggedTwiceWithTheSameAliasIsAccepted(
        CompilerPassInterface $pass,
        string $factory,
        string $tag,
        string $label,
        string $serviceClass,
        array $serviceArguments
    ): void {
        $container = $this->createContainer($pass, $factory);
        $container->register('app.service', $serviceClass)
            ->setArguments($serviceArguments)
            ->setPublic(true)
            ->addTag($tag, [
                'alias' => 'shared',
            ])
            ->addTag($tag, [
                'alias' => 'shared',
            ]);

        $container->compile(true);

        static::assertSame([
            'shared' => $container->get('app.service'),
        ], $this->registeredServices($container, $factory));
    }

    /**
     * @param class-string $factory
     * @param list<mixed> $serviceArguments
     */
    #[DataProvider('dataPasses')]
    #[Test]
    public function servicesWithAliasesOfTheirOwnAreAccepted(
        CompilerPassInterface $pass,
        string $factory,
        string $tag,
        string $label,
        string $serviceClass,
        array $serviceArguments
    ): void {
        $container = $this->createContainer($pass, $factory);
        $container->register('app.first', $serviceClass)
            ->setArguments($serviceArguments)
            ->setPublic(true)
            ->addTag($tag, [
                'alias' => 'first',
            ]);
        $container->register('app.second', $serviceClass)
            ->setArguments($serviceArguments)
            ->setPublic(true)
            ->addTag($tag, [
                'alias' => 'second',
            ])
            ->addTag($tag, [
                'alias' => 'second_again',
            ]);

        $container->compile(true);

        static::assertSame([
            'first' => $container->get('app.first'),
            'second' => $container->get('app.second'),
            'second_again' => $container->get('app.second'),
        ], $this->registeredServices($container, $factory));
    }

    /**
     * @param class-string $factory
     * @param list<mixed> $serviceArguments
     */
    #[DataProvider('dataPasses')]
    #[Test]
    public function aServiceTaggedWithoutAliasIsRefused(
        CompilerPassInterface $pass,
        string $factory,
        string $tag,
        string $label,
        string $serviceClass,
        array $serviceArguments
    ): void {
        $container = $this->createContainer($pass, $factory);
        $container->register('app.service', $serviceClass)
            ->setArguments($serviceArguments)
            ->addTag($tag);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The %s "app.service" does not have any "alias" attribute.', $label));

        $container->compile(true);
    }

    /**
     * @return iterable<string, array{CompilerPassInterface, class-string, string, string, class-string, list<mixed>}>
     */
    public static function dataPasses(): iterable
    {
        yield 'header checkers' => [
            new HeaderCheckerCompilerPass(),
            HeaderCheckerManagerFactory::class,
            'jose.checker.header',
            'header checker',
            AudienceChecker::class,
            ['api'],
        ];
        yield 'claim checkers' => [
            new ClaimCheckerCompilerPass(),
            ClaimCheckerManagerFactory::class,
            'jose.checker.claim',
            'claim checker',
            AudienceChecker::class,
            ['api'],
        ];
        yield 'algorithms' => [
            new AlgorithmCompilerPass(),
            AlgorithmManagerFactory::class,
            'jose.algorithm',
            'algorithm',
            HS256::class,
            [],
        ];
    }

    /**
     * @param class-string $factory
     */
    private function createContainer(CompilerPassInterface $pass, string $factory): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->register('event_dispatcher', EventDispatcher::class);
        $container->register($factory, $factory)
            ->setArguments($factory === AlgorithmManagerFactory::class ? [] : [new Reference('event_dispatcher')])
            ->setPublic(true);
        $container->addCompilerPass($pass);

        return $container;
    }

    /**
     * @param class-string $factory
     *
     * @return array<string, object>
     */
    private function registeredServices(ContainerBuilder $container, string $factory): array
    {
        $instance = $container->get($factory);
        static::assertInstanceOf($factory, $instance);

        return $instance->all();
    }
}
