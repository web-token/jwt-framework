<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use Ergebnis\PHPUnit\SlowTestDetector\Attribute\MaximumDuration;
use InvalidArgumentException;
use Jose\Component\Console\EcKeysetGeneratorCommand;
use Jose\Component\Console\OctKeysetGeneratorCommand;
use Jose\Component\Console\OkpKeysetGeneratorCommand;
use Jose\Component\Console\RsaKeysetGeneratorCommand;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @internal
 */
final class KeySetCreationCommandTest extends TestCase
{
    #[Test]
    public function theEllipticCurveKeySetCreationCommandIsAvailable(): void
    {
        $command = new EcKeysetGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    #[Test]
    public function theEllipticCurveKeySetCreationCommandNeedTheCurveAndQuantityArguments(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "quantity, curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new EcKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    #[Test]
    public function iCannotCreateAnEllipticCurveKeySetWithAnUnsupportedCurve(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve "P-128" is not supported.');

        $input = new ArrayInput([
            'quantity' => 2,
            'curve' => 'P-128',
        ]);
        $output = new BufferedOutput();
        $command = new EcKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    #[Test]
    public function iCanCreateAnEllipticCurveKeySetWithCurveP256(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'curve' => 'P-256',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new EcKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwkset = JWKSet::createFromJson($content);
        static::assertCount(2, $jwkset, 'Invalid number of keys in the keyset');
    }

    #[Test]
    public function iCannotCreateAnOctetKeySetWithoutKeySetSize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([
            'quantity' => 2,
        ]);
        $output = new BufferedOutput();
        $command = new OctKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwkset = JWKSet::createFromJson($content);
        static::assertCount(2, $jwkset, 'Invalid number of keys in the keyset');
    }

    #[Test]
    public function iCanCreateAnOctetKeySet(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'size' => 256,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new OctKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwkset = JWKSet::createFromJson($content);
        static::assertCount(2, $jwkset, 'Invalid number of keys in the keyset');
    }

    #[Test]
    public function iCannotCreateAnOctetKeySetPairWithoutKeySetCurve(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([
            'quantity' => 2,
        ]);
        $output = new BufferedOutput();
        $command = new OkpKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    #[Test]
    public function iCanCreateAnOctetKeySetPair(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'curve' => 'X25519',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new OkpKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwkset = JWKSet::createFromJson($content);
        static::assertCount(2, $jwkset, 'Invalid number of keys in the keyset');
    }

    #[Test]
    public function iCannotCreateAnRsaKeySetWithoutKeySetSize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([
            'quantity' => 2,
        ]);
        $output = new BufferedOutput();
        $command = new RsaKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    #[Test]
    #[MaximumDuration(500)]
    public function iCanCreateAnRsaKeySet(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'size' => 2048,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new RsaKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwkset = JWKSet::createFromJson($content);
        static::assertCount(2, $jwkset, 'Invalid number of keys in the keyset');
    }
}
