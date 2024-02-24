<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\Signature;

use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Signature\SignatureSource;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JwsBuilderConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    #[Test]
    public function theConfigurationIsValidIfNoConfigurationIsSet(): void
    {
        $this->assertConfigurationIsValid([]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsFalse(): void
    {
        $this->assertConfigurationIsValid([
            [
                'jws' => false,
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsEmpty(): void
    {
        $this->assertConfigurationIsValid([
            [
                'jws' => [],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsInvalidIfBuilderIsSet(): void
    {
        $this->assertConfigurationIsValid([
            [
                'jws' => [
                    'builders' => [],
                ],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsInvalidIfNotSignatureAlgorithmIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'builders' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child config "signature_algorithms" under "jose.jws.builders.foo" must be configured:'
        );
    }

    #[Test]
    public function theConfigurationIsInvalidIfTheSignatureAlgorithmIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'builders' => [
                            'foo' => [
                                'signature_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jws.builders.foo.signature_algorithms" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new SignatureSource()]);
    }
}
