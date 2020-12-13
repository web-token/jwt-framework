<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Console;

use Base64Url\Base64Url;
use InvalidArgumentException;
use Jose\Component\Console;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @group Console
 * @group KeyCreationCommand
 *
 * @internal
 */
class KeyCreationCommandTest extends TestCase
{
    /**
     * @test
     */
    public function theEllipticCurveKeyCreationCommandIsAvailable(): void
    {
        $command = new Console\EcKeyGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    /**
     * @test
     */
    public function theEllipticCurveKeyCreationCommandNeedTheCurveArgument(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new Console\EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCannotCreateAnEllipticCurveKeyWithAnUnsupportedCurve(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve "P-128" is not supported.');

        $input = new ArrayInput([
            'curve' => 'P-128',
        ]);
        $output = new BufferedOutput();
        $command = new Console\EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnEllipticCurveKeyWithCurveP256(): void
    {
        $input = new ArrayInput([
            'curve' => 'P-256',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\EcKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCannotCreateAnOctetKeyWithoutKeySize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([
        ]);
        $output = new BufferedOutput();
        $command = new Console\OctKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKey(): void
    {
        $input = new ArrayInput([
            'size' => 256,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OctKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeyUsingASecret(): void
    {
        $input = new ArrayInput([
            'secret' => 'This is my secret',
        ]);
        $output = new BufferedOutput();
        $command = new Console\SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertTrue($jwk->has('k'));
        static::assertEquals('This is my secret', Base64Url::decode($jwk->get('k')));
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeyUsingABinarySecret(): void
    {
        $secret = random_bytes(20);

        $input = new ArrayInput([
            'secret' => $secret,
            '--is_b64',
        ]);
        $output = new BufferedOutput();
        $command = new Console\SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertTrue($jwk->has('k'));
        static::assertEquals($secret, Base64Url::decode($jwk->get('k')));
    }

    /**
     * @test
     */
    public function iCannotCreateAnOctetKeyPairWithoutKeyCurve(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([
        ]);
        $output = new BufferedOutput();
        $command = new Console\OkpKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeyPair(): void
    {
        $input = new ArrayInput([
            'curve' => 'X25519',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OkpKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCanCreateANoneKey(): void
    {
        $input = new ArrayInput([
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\NoneKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCannotCreateAnRsaKeyWithoutKeySize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnRsaKey(): void
    {
        $input = new ArrayInput([
            'size' => 2048,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }
}
