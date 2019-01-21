<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console\Tests;

use Jose\Component\Console;
use Jose\Component\Core\JWKSet;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @group Console
 * @group KeySetCreationCommand
 */
class KeySetCreationCommandTest extends TestCase
{
    /**
     * @test
     */
    public function theEllipticCurveKeySetCreationCommandIsAvailable()
    {
        $command = new Console\EcKeysetGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "quantity, curve").
     */
    public function theEllipticCurveKeySetCreationCommandNeedTheCurveAndQuantityArguments()
    {
        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new Console\EcKeysetGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The curve "P-128" is not supported.
     */
    public function iCannotCreateAnEllipticCurveKeySetWithAnUnsupportedCurve()
    {
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
    public function iCanCreateAnEllipticCurveKeySetWithCurveP256()
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
        $jwk = JWKSet::createFromJson($content);
        static::assertInstanceOf(JWKSet::class, $jwk);
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "size").
     */
    public function iCannotCreateAnOctetKeySetWithoutKeySetSize()
    {
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
    public function iCanCreateAnOctetKeySet()
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
        $jwk = JWKSet::createFromJson($content);
        static::assertInstanceOf(JWKSet::class, $jwk);
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "curve").
     */
    public function iCannotCreateAnOctetKeySetPairWithoutKeySetCurve()
    {
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
    public function iCanCreateAnOctetKeySetPair()
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
        $jwk = JWKSet::createFromJson($content);
        static::assertInstanceOf(JWKSet::class, $jwk);
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "size").
     */
    public function iCannotCreateAnRsaKeySetWithoutKeySetSize()
    {
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
    public function iCanCreateAnRsaKeySet()
    {
        $input = new ArrayInput([
            'quantity' => 2,
            'size' => 1024,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeysetGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWKSet::createFromJson($content);
        static::assertInstanceOf(JWKSet::class, $jwk);
    }
}
