<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console\Tests;

use Jose\Component\Console;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\Serializer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Helper\HelperSet;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @group Console
 * @group SignedTokenCreationCommand
 */
class SignedTokenCreationCommandTest extends TestCase
{
    private $command;
    private $algorithmManagerFactory;
    private $serializerManagerFactory;

    /**
     * @test
     */
    public function iCanAnalyzeAKeyAndGetInformation()
    {
        $commandTester = new CommandTester($this->getCommand());
        $commandTester->setInputs([
            '2',
            '{"FooBar":true}',
            '{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}',
            'alg', 'ES256', 'iss', 'foo', 'aud', 'bar', null,
            null,
            null,
            'jws_json_general',
        ]);
        $commandTester->execute([]);
    }

    private function getCommand(): Console\CreateSignedTokenCommand
    {
        if (!$this->command) {
            $this->command = new Console\CreateSignedTokenCommand(
                new StandardConverter(),
                $this->getAlgorithmManagerFactory(),
                $this->getSerializerManagerFactory()
            );
            $this->command->setHelperSet(new HelperSet([
                new QuestionHelper(),
            ]));
        }

        return $this->command;
    }

    private function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (!$this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('HS256', new Algorithm\HS256());
            $this->algorithmManagerFactory->add('RS256', new Algorithm\RS256());
            $this->algorithmManagerFactory->add('ES256', new Algorithm\ES256());
        }

        return $this->algorithmManagerFactory;
    }

    private function getSerializerManagerFactory(): Serializer\JWSSerializerManagerFactory
    {
        if (!$this->serializerManagerFactory) {
            $this->serializerManagerFactory = new Serializer\JWSSerializerManagerFactory();
            $this->serializerManagerFactory->add(new Serializer\CompactSerializer(new StandardConverter()));
            $this->serializerManagerFactory->add(new Serializer\JSONFlattenedSerializer(new StandardConverter()));
            $this->serializerManagerFactory->add(new Serializer\JSONGeneralSerializer(new StandardConverter()));
        }

        return $this->serializerManagerFactory;
    }
}
