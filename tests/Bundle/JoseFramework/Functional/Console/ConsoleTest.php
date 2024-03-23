<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Console;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * @internal
 */
final class ConsoleTest extends KernelTestCase
{
    #[Test]
    public static function allCommandsAreAvailable(): void
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

        foreach ($expectedCommands as $expectedCommand) {
            static::assertArrayHasKey($expectedCommand, $application->all());
        }
    }
}
