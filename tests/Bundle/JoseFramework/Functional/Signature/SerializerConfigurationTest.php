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
final class SerializerConfigurationTest extends TestCase
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
    public function theConfigurationIsValidIfNoSerializerIsSet(): void
    {
        $this->assertConfigurationIsValid([
            [
                'jws' => [
                    'serializers' => [],
                ],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsInvalidIfNoSerializerParameterIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'serializers' => [
                            'foo' => [],
                        ],
                    ],
                ],
            ],
            'The child config "serializers" under "jose.jws.serializers.foo" must be configured:'
        );
    }

    #[Test]
    public function theConfigurationIsInvalidIfTheSerializerListIsEmpty(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jws' => [
                        'serializers' => [
                            'foo' => [
                                'serializers' => [],
                            ],
                        ],
                    ],
                ],
            ],
            'The path "jose.jws.serializers.foo.serializers" should have at least 1 element(s) defined.'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new SignatureSource()]);
    }
}
