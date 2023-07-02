<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use Jose\Component\Console\KeyAnalyzerCommand;
use Jose\Component\Console\KeysetAnalyzerCommand;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MixedKeyTypes;
use Jose\Component\KeyManagement\Analyzer\MixedPublicAndPrivateKeys;
use Jose\Component\KeyManagement\Analyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\Analyzer\OctAnalyzer;
use Jose\Component\KeyManagement\Analyzer\RsaAnalyzer;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * @internal
 */
final class AnalyzeCommandTest extends TestCase
{
    private ?KeyAnalyzerManager $keyAnalyzerManager = null;

    private ?KeysetAnalyzerManager $keysetAnalyzerManager = null;

    #[Test]
    public function iCanAnalyzeAKeyAndGetInformation(): void
    {
        $jwk = new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
        ]);

        $input = new ArrayInput([
            'jwk' => JsonConverter::encode($jwk),
        ]);
        $output = new BufferedOutput();
        $command = new KeyAnalyzerCommand($this->getKeyAnalyzer());
        $command->run($input, $output);
        $content = $output->fetch();
        static::assertStringContainsString('* The parameter "alg" should be added.', $content);
        static::assertStringContainsString('* The parameter "kid" should be added.', $content);
        static::assertStringContainsString('* The parameter "use" should be added.', $content);
    }

    #[Test]
    public function iCanAnalyzeAKeySetAndGetInformation(): void
    {
        $keyset = JWKSet::createFromKeyData([
            'keys' => [
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
            ],
        ]);

        $input = new ArrayInput([
            'jwkset' => JsonConverter::encode($keyset),
        ]);
        $output = new BufferedOutput();
        $command = new KeysetAnalyzerCommand($this->getKeysetAnalyzer(), $this->getKeyAnalyzer());
        $command->run($input, $output);
        $content = $output->fetch();
        static::assertStringContainsString('Analysing key with index/kid "1"', $content);
        static::assertStringContainsString('* The parameter "alg" should be added.', $content);
        static::assertStringContainsString('* The parameter "kid" should be added.', $content);
        static::assertStringContainsString('* The parameter "use" should be added.', $content);
    }

    private function getKeyAnalyzer(): KeyAnalyzerManager
    {
        if ($this->keyAnalyzerManager === null) {
            $this->keyAnalyzerManager = new KeyAnalyzerManager();
            $this->keyAnalyzerManager->add(new AlgorithmAnalyzer());
            $this->keyAnalyzerManager->add(new KeyIdentifierAnalyzer());
            $this->keyAnalyzerManager->add(new NoneAnalyzer());
            $this->keyAnalyzerManager->add(new OctAnalyzer());
            $this->keyAnalyzerManager->add(new RsaAnalyzer());
            $this->keyAnalyzerManager->add(new UsageAnalyzer());
        }

        return $this->keyAnalyzerManager;
    }

    private function getKeysetAnalyzer(): KeysetAnalyzerManager
    {
        if ($this->keysetAnalyzerManager === null) {
            $this->keysetAnalyzerManager = new KeysetAnalyzerManager();
            $this->keysetAnalyzerManager->add(new MixedKeyTypes());
            $this->keysetAnalyzerManager->add(new MixedPublicAndPrivateKeys());
        }

        return $this->keysetAnalyzerManager;
    }
}
