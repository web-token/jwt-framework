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

use InvalidArgumentException;
use Jose\Component\Console;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @group Console
 * @group KeySetCreationCommand
 *
 * @internal
 */
class KeySetCreationCommandTest extends TestCase
{
    /**
     * @test
     */
    public function theEllipticCurveKeySetCreationCommandIsAvailable(): void
    {
        $command = new Console\EcKeysetGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    /**
     * @test
     */
    public function theEllipticCurveKeySetCreationCommandNeedTheCurveAndQuantityArguments(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "quantity, curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new Console\EcKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCannotCreateAnEllipticCurveKeySetWithAnUnsupportedCurve(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve "P-128" is not supported.');

        $input = new ArrayInput([
            'quantity' => 2,
            'curve' => 'P-128',
        ]);
        $output = new BufferedOutput();
        $command = new Console\EcKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnEllipticCurveKeySetWithCurveP256(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'curve' => 'P-256',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\EcKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWKSet::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCannotCreateAnOctetKeySetWithoutKeySetSize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([
            'quantity' => 2,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OctKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeySet(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'size' => 256,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OctKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWKSet::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCannotCreateAnOctetKeySetPairWithoutKeySetCurve(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([
            'quantity' => 2,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OkpKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeySetPair(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'curve' => 'X25519',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OkpKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWKSet::createFromJson($content);
    }

    /**
     * @test
     */
    public function iCannotCreateAnRsaKeySetWithoutKeySetSize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([
            'quantity' => 2,
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnRsaKeySet(): void
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'size' => 2048,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWKSet::createFromJson($content);
    }
}
