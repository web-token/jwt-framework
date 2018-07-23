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
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\KeyAnalyzer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @group Console
 * @group AnalyzeCommand
 */
class AnalyzeCommandTest extends TestCase
{
    /**
     * @test
     */
    public function iCanAnalyzeAKeyAndGetInformation()
    {
        $jwk = JWK::create([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
        ]);
        $converter = new StandardConverter();
        $input = new ArrayInput([
            'jwk' => $converter->encode($jwk),
        ]);
        $output = new BufferedOutput();
        $command = new Console\KeyAnalyzerCommand($this->getKeyAnalyzer(), $converter);
        $command->run($input, $output);
        $content = $output->fetch();
        self::assertContains('* The parameter "alg" should be added.', $content);
        self::assertContains('* The parameter "kid" should be added.', $content);
        self::assertContains('* The parameter "use" should be added.', $content);
    }

    /**
     * @test
     */
    public function iCanAnalyzeAKeySetAndGetInformation()
    {
        $keyset = JWKSet::createFromKeyData(['keys' => [
            [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            ],
            [
                'kty' => 'EC',
                'crv' => 'P-521',
                'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
                'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            ],
        ]]);
        $converter = new StandardConverter();
        $input = new ArrayInput([
            'jwkset' => $converter->encode($keyset),
        ]);
        $output = new BufferedOutput();
        $command = new Console\KeysetAnalyzerCommand($this->getKeyAnalyzer(), $converter);
        $command->run($input, $output);
        $content = $output->fetch();
        self::assertContains('Analysing key with index/kid "1"', $content);
        self::assertContains('* The parameter "alg" should be added.', $content);
        self::assertContains('* The parameter "kid" should be added.', $content);
        self::assertContains('* The parameter "use" should be added.', $content);
    }

    /**
     * @var KeyAnalyzer\KeyAnalyzerManager|null
     */
    private $keyAnalyzerManager;

    private function getKeyAnalyzer(): KeyAnalyzer\KeyAnalyzerManager
    {
        if (null === $this->keyAnalyzerManager) {
            $this->keyAnalyzerManager = new KeyAnalyzer\KeyAnalyzerManager();
            $this->keyAnalyzerManager
                ->add(new KeyAnalyzer\AlgorithmAnalyzer())
                ->add(new KeyAnalyzer\KeyIdentifierAnalyzer())
                ->add(new KeyAnalyzer\NoneAnalyzer())
                ->add(new KeyAnalyzer\OctAnalyzer())
                ->add(new KeyAnalyzer\RsaAnalyzer())
                ->add(new KeyAnalyzer\UsageAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }
}
