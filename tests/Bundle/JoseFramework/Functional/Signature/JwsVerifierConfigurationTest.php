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
final class JwsVerifierConfigurationTest extends TestCase
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
                    'verifiers' => [],
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
                        'verifiers' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child config "signature_algorithms" under "jose.jws.verifiers.foo" must be configured:'
        );
    }

    #[Test]
    public function theConfigurationIsInvalidIfTheSignatureAlgorithmIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'verifiers' => [
                            'foo' => [
                                'signature_algorithms' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jws.verifiers.foo.signature_algorithms" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new SignatureSource()]);
    }
}
