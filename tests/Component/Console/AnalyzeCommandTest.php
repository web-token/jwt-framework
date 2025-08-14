<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Tests\Bundle\JoseFramework\KernelTestCase;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * @internal
 */
final class AnalyzeCommandTest extends KernelTestCase
{
    #[Test]
    public function iCanAnalyzeAKeyAndGetInformation(): void
    {
        // Given
        $jwk = new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
        ]);

        $command = (new Application(self::bootKernel()))->find('key:analyze');
        $commandTester = new CommandTester($command);

        // When
        $commandTester->execute([
            'jwk' => JsonConverter::encode($jwk),
        ]);

        // Then
        $commandTester->assertCommandIsSuccessful();
        $output = $commandTester->getDisplay();

        static::assertStringContainsString('* The parameter "alg" should be added.', $output);
        static::assertStringContainsString('* The parameter "kid" should be added.', $output);
        static::assertStringContainsString('* The parameter "use" should be added.', $output);
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

        $command = (new Application(self::bootKernel()))->find('keyset:analyze');
        $commandTester = new CommandTester($command);
        // When
        $commandTester->execute([
            'jwkset' => JsonConverter::encode($keyset),
        ]);

        // Then
        $commandTester->assertCommandIsSuccessful();
        $output = $commandTester->getDisplay();

        static::assertStringContainsString('Analysing key with index/kid "1"', $output);
        static::assertStringContainsString('* The parameter "alg" should be added.', $output);
        static::assertStringContainsString('* The parameter "kid" should be added.', $output);
        static::assertStringContainsString('* The parameter "use" should be added.', $output);
    }
}
