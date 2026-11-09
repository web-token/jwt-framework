<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use Jose\Component\Console\EcKeyGeneratorCommand;
use Jose\Component\Console\GeneratorCommand;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactoryInterface;
use Override;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;
use function array_filter;

/**
 * The key factory reaches the generator commands through a setter, so that the abstract command keeps publishing
 * exactly what it published before it gained the dependency: an application command extending it, with or without a
 * constructor of its own, is left untouched.
 *
 * @internal
 */
final class GeneratorCommandBcTest extends TestCase
{
    #[Test]
    public function theConstructorInheritedFromTheSymfonyCommandIsUntouched(): void
    {
        $constructor = (new ReflectionClass(GeneratorCommand::class))->getConstructor();

        static::assertNotNull($constructor);
        static::assertSame(Command::class, $constructor->getDeclaringClass()->getName());
    }

    #[Test]
    public function theAbstractCommandDeclaresNoPropertyASubclassCouldClashWith(): void
    {
        $reflection = new ReflectionClass(GeneratorCommand::class);
        $properties = array_filter(
            $reflection->getProperties(ReflectionProperty::IS_PUBLIC | ReflectionProperty::IS_PROTECTED),
            static fn (ReflectionProperty $property): bool => $property->getDeclaringClass()
                ->getName() === GeneratorCommand::class
        );

        static::assertSame([], $properties);
    }

    #[Test]
    public function aCommandKeepsTheNameGivenToItsConstructor(): void
    {
        $command = new EcKeyGeneratorCommand('my:command');

        static::assertSame('my:command', $command->getName());
    }

    #[Test]
    public function aSubclassWithItsOwnConstructorStillBuildsAndRuns(): void
    {
        $command = new class('my:command') extends GeneratorCommand {
            public function __construct(?string $name = null)
            {
                parent::__construct($name);
            }

            #[Override]
            protected function execute(InputInterface $input, OutputInterface $output): int
            {
                $this->prepareJsonOutput($input, $output, $this->getJwkFactory()->oct(256));

                return self::SUCCESS;
            }
        };

        $output = new BufferedOutput();
        $command->run(new ArrayInput([]), $output);

        static::assertSame('my:command', $command->getName());
        static::assertSame('oct', JWK::createFromJson($output->fetch())->get('kty'));
    }

    #[Test]
    public function anInjectedFactoryReplacesTheDefaultOne(): void
    {
        $factory = static::createStub(JWKFactoryInterface::class);
        $factory->method('ec')
            ->willReturn(new JWK([
                'kty' => 'oct',
                'k' => 'aW5qZWN0ZWQ',
            ]));
        $command = new EcKeyGeneratorCommand();
        $command->setJwkFactory($factory);

        $output = new BufferedOutput();
        $command->run(new ArrayInput([
            'curve' => 'P-256',
        ]), $output);

        static::assertSame('aW5qZWN0ZWQ', JWK::createFromJson($output->fetch())->get('k'));
    }
}
