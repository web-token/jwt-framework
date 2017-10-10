<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\Console\Tests;

use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * @group Bundle
 * @group Functional
 */
final class ConsoleTest extends KernelTestCase
{
    public function testAllCommandsAreAvailable()
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

        self::assertEmpty(array_diff($expectedCommands, array_keys($application->all())));
    }
}
