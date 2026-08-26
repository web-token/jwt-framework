<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use InvalidArgumentException;
use Jose\Component\Console\EcKeyGeneratorCommand;
use Jose\Component\Console\NoneKeyGeneratorCommand;
use Jose\Component\Console\OctKeyGeneratorCommand;
use Jose\Component\Console\OkpKeyGeneratorCommand;
use Jose\Component\Console\RsaKeyGeneratorCommand;
use Jose\Component\Console\SecretKeyGeneratorCommand;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @internal
 */
final class KeyCreationCommandTest extends TestCase
{
    #[Test]
    public function theEllipticCurveKeyCreationCommandIsAvailable(): void
    {
        $command = new EcKeyGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    #[Test]
    public function theEllipticCurveKeyCreationCommandNeedTheCurveArgument(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[Test]
    public function iCannotCreateAnEllipticCurveKeyWithAnUnsupportedCurve(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve "P-128" is not supported.');

        $input = new ArrayInput([
            'curve' => 'P-128',
        ]);
        $output = new BufferedOutput();
        $command = new EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnEllipticCurveKeyWithCurveP256(): void
    {
        $input = new ArrayInput([
            'curve' => 'P-256',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new EcKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[Test]
    public function iCannotCreateAnOctetKeyWithoutKeySize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new OctKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnOctetKey(): void
    {
        $input = new ArrayInput([
            'size' => 256,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new OctKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[Test]
    public function iCanCreateAnOctetKeyUsingASecret(): void
    {
        $input = new ArrayInput([
            'secret' => 'This is my secret',
        ]);
        $output = new BufferedOutput();
        $command = new SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertTrue($jwk->has('k'));
        static::assertSame('This is my secret', Base64UrlSafe::decode($jwk->get('k')));
    }

    #[Test]
    public function iCanCreateAnOctetKeyUsingABinarySecret(): void
    {
        $secret = random_bytes(20);

        $input = new ArrayInput([
            'secret' => $secret,
            '--is_b64',
        ]);
        $output = new BufferedOutput();
        $command = new SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertTrue($jwk->has('k'));
        static::assertSame($secret, Base64UrlSafe::decode($jwk->get('k')));
    }

    #[Test]
    public function iCannotCreateAnOctetKeyPairWithoutKeyCurve(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new OkpKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnOctetKeyPair(): void
    {
        $input = new ArrayInput([
            'curve' => 'X25519',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new OkpKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateANoneKey(): void
    {
        $input = new ArrayInput([
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new NoneKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[Test]
    public function iCannotCreateAnRsaKeyWithoutKeySize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new RsaKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnRsaKey(): void
    {
        $input = new ArrayInput([
            'size' => 2048,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new RsaKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }
}
