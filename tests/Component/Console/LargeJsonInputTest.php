<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use Jose\Component\Console\GetThumbprintCommand;
use Jose\Component\Console\KeyAnalyzerCommand;
use Jose\Component\Console\KeysetAnalyzerCommand;
use Jose\Component\Console\OptimizeRsaKeyCommand;
use Jose\Component\Console\PemConverterCommand;
use Jose\Component\Console\Pkcs8ConverterCommand;
use Jose\Component\Console\PublicKeyCommand;
use Jose\Component\Console\PublicKeysetCommand;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use function range;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

/**
 * The commands decode the keys of the operator without the bound of the JSON documents of a token: a key of more than
 * 4096 JSON values is decoded, without deprecation.
 *
 * @internal
 */
final class LargeJsonInputTest extends TestCase
{
    /**
     * @param array<string, string> $arguments
     */
    #[Test]
    #[DataProvider('commands')]
    public function aCommandDecodesALargeKeyWithoutDeprecation(Command $command, array $arguments): void
    {
        $deprecations = [];
        set_error_handler(static function (int $type, string $message) use (&$deprecations): bool {
            $deprecations[] = $message;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $exitCode = $command->run(new ArrayInput($arguments), new BufferedOutput());
        } finally {
            restore_error_handler();
        }

        static::assertSame(Command::SUCCESS, $exitCode);
        static::assertSame([], $deprecations);
    }

    /**
     * @return iterable<string, array{Command, array<string, string>}>
     */
    public static function commands(): iterable
    {
        $padding = range(1, 5000);
        $ec = (new JWKFactory())->ec('P-256', [
            'padding' => $padding,
        ])->all();
        $rsa = (new JWKFactory())->rsa(2048, [
            'padding' => $padding,
        ])->all();
        $key = JsonConverter::encode($ec);
        $keySet = JsonConverter::encode([
            'keys' => [$ec],
        ]);

        yield 'thumbprint' => [new GetThumbprintCommand(), [
            'jwk' => $key,
        ]];
        yield 'key analyzer' => [new KeyAnalyzerCommand(new KeyAnalyzerManager()), [
            'jwk' => $key,
        ]];
        yield 'key set analyzer' => [
            new KeysetAnalyzerCommand(new KeysetAnalyzerManager(), new KeyAnalyzerManager()),
            [
                'jwkset' => $keySet,
            ],
        ];
        yield 'RSA optimization' => [new OptimizeRsaKeyCommand(), [
            'jwk' => JsonConverter::encode($rsa),
        ]];
        yield 'PEM conversion' => [new PemConverterCommand(), [
            'jwk' => $key,
        ]];
        yield 'PKCS#8 conversion' => [new Pkcs8ConverterCommand(), [
            'jwk' => $key,
        ]];
        yield 'public key' => [new PublicKeyCommand(), [
            'jwk' => $key,
        ]];
        yield 'public key set' => [new PublicKeysetCommand(), [
            'jwkset' => $keySet,
        ]];
    }
}
