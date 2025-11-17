<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use Jose\Tests\Bundle\JoseFramework\KernelTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use function sprintf;

/**
 * @internal
 * Test to ensure commands are compatible with Symfony Console 7.0+
 * by using setHelp() instead of the help parameter in AsCommand attribute
 */
final class CommandHelpCompatibilityTest extends KernelTestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function commandsWithExpectedHelpTextProvider(): iterable
    {
        yield 'key:analyze' => ['key:analyze', 'JWK object'];
        yield 'key:convert:public' => ['key:convert:public', 'private key into a public key'];
        yield 'keyset:analyze' => ['keyset:analyze', 'JWKSet object'];
        yield 'keyset:add:key' => ['keyset:add:key', 'key at the end'];
        yield 'keyset:rotate' => ['keyset:rotate', 'last key'];
        yield 'keyset:merge' => ['keyset:merge', 'several key sets'];
        yield 'keyset:load:jku' => ['keyset:load:jku', 'JWKSet'];
        yield 'keyset:load:x5u' => ['keyset:load:x5u', 'X.509 certificates'];
        yield 'keyset:convert:public' => ['keyset:convert:public', 'private keys in a key set into public keys'];
    }

    #[Test]
    #[DataProvider('commandsWithExpectedHelpTextProvider')]
    public function commandsHaveHelpTextDefinedViaSetHelpMethod(string $commandName, string $expectedSubstring): void
    {
        // Given
        $application = new Application(self::bootKernel());

        // When
        $command = $application->find($commandName);
        $helpText = $command->getHelp();

        // Then
        static::assertNotEmpty($helpText, sprintf('Command "%s" should have help text defined', $commandName));
        static::assertStringContainsString(
            $expectedSubstring,
            $helpText,
            sprintf('Command "%s" help text should contain "%s"', $commandName, $expectedSubstring)
        );
    }

    #[Test]
    public function allCommandsHaveNonEmptyHelpText(): void
    {
        // Given
        $application = new Application(self::bootKernel());
        $commandNames = [
            'key:analyze',
            'key:convert:public',
            'keyset:analyze',
            'keyset:add:key',
            'keyset:rotate',
            'keyset:merge',
            'keyset:load:jku',
            'keyset:load:x5u',
            'keyset:convert:public',
        ];

        // When & Then
        foreach ($commandNames as $commandName) {
            $command = $application->find($commandName);
            static::assertNotEmpty(
                $command->getHelp(),
                sprintf('Command "%s" must have help text for Symfony Console 7.0 compatibility', $commandName)
            );
        }
    }
}
