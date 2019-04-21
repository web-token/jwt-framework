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

use Base64Url\Base64Url;
use Jose\Component\Console;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @group Console
 * @group KeyCreationCommand
 *
 * @internal
 * @coversNothing
 */
class KeyCreationCommandTest extends TestCase
{
    /**
     * @test
     */
    public function theEllipticCurveKeyCreationCommandIsAvailable()
    {
        $command = new Console\EcKeyGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "curve").
     */
    public function theEllipticCurveKeyCreationCommandNeedTheCurveArgument()
    {
        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new Console\EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The curve "P-128" is not supported.
     */
    public function iCannotCreateAnEllipticCurveKeyWithAnUnsupportedCurve()
    {
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
    public function iCanCreateAnEllipticCurveKeyWithCurveP256()
    {
        $input = new ArrayInput([
            'curve' => 'P-256',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\EcKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "size").
     */
    public function iCannotCreateAnOctetKeyWithoutKeySize()
    {
        $input = new ArrayInput([
        ]);
        $output = new BufferedOutput();
        $command = new Console\OctKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKey()
    {
        $input = new ArrayInput([
            'size' => 256,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OctKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeyUsingASecret()
    {
        $input = new ArrayInput([
            'secret' => 'This is my secret',
        ]);
        $output = new BufferedOutput();
        $command = new Console\SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertTrue($jwk->has('k'));
        static::assertEquals('This is my secret', Base64Url::decode($jwk->get('k')));
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeyUsingABinarySecret()
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
        static::assertInstanceOf(JWK::class, $jwk);
        static::assertTrue($jwk->has('k'));
        static::assertEquals($secret, Base64Url::decode($jwk->get('k')));
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "curve").
     */
    public function iCannotCreateAnOctetKeyPairWithoutKeyCurve()
    {
        $input = new ArrayInput([
        ]);
        $output = new BufferedOutput();
        $command = new Console\OkpKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnOctetKeyPair()
    {
        $input = new ArrayInput([
            'curve' => 'X25519',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\OkpKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @test
     */
    public function iCanCreateANoneKey()
    {
        $input = new ArrayInput([
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\NoneKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertInstanceOf(JWK::class, $jwk);
    }

    /**
     * @test
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Not enough arguments (missing: "size").
     */
    public function iCannotCreateAnRsaKeyWithoutKeySize()
    {
        $input = new ArrayInput([
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeyGeneratorCommand();

        $command->run($input, $output);
    }

    /**
     * @test
     */
    public function iCanCreateAnRsaKey()
    {
        $input = new ArrayInput([
            'size' => 2048,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new Console\RsaKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertInstanceOf(JWK::class, $jwk);
    }
}
