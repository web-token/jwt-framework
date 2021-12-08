<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Console;

use Jose\Component\Console\EcKeyGeneratorCommand;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * @internal
 */
final class ConsoleTest extends KernelTestCase
{
    protected function setUp(): void
    {
        if (! class_exists(EcKeyGeneratorCommand::class)) {
            static::markTestSkipped('The component "web-token/jwt-console" is not installed.');
        }
    }

    /**
     * @test
     */
    public function allCommandsAreAvailable(): void
    {
        $expectedCommands = [
            'keyset:add:key',
            'key:generate:ec',
            'keyset:generate:ec',
            'key:thumbprint',
            'key:analyze',
            'key:load:key',
            'keyset:analyze',
            'keyset:merge',
            'key:generate:oct',
            'keyset:generate:oct',
            'key:generate:okp',
            'keyset:generate:okp',
            'key:optimize',
            'key:load:p12',
            'key:convert:pkcs1',
            'keyset:convert:public',
            'keyset:rotate',
            'key:generate:rsa',
            'keyset:generate:rsa',
            'key:load:x509',
        ];
        self::bootKernel();
        $application = new Application(self::$kernel);

        static::assertEmpty(array_diff($expectedCommands, array_keys($application->all())));
    }
}
