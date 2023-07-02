<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use PHPUnit\Framework\Attributes\Test;
use Jose\Bundle\JoseFramework\DependencyInjection\Configuration;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\Core\CoreSource;
use Jose\Bundle\JoseFramework\DependencyInjection\Source\KeyManagement\KeyManagementSource;
use Jose\Component\KeyManagement\JWKFactory;
use Matthias\SymfonyConfigTest\PhpUnit\ConfigurationTestCaseTrait;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
final class JwkUriConfigurationTest extends TestCase
{
    use ConfigurationTestCaseTrait;

    protected function setUp(): void
    {
        if (! class_exists(JWKFactory::class)) {
            static::markTestSkipped('The component "web-token/jwt-key-mgmt" is not installed.');
        }
    }

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
                'jwk_uris' => false,
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsValidIfConfigurationIsEmpty(): void
    {
        $this->assertConfigurationIsValid([
            [
                'jwk_uris' => [],
            ],
        ]);
    }

    #[Test]
    public function theConfigurationIsInvalidIfNoKeySetIdIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwk_uris' => [
                        'foo' => [],
                    ],
                ],
            ],
            'The child config "id" under "jose.jwk_uris.foo" must be configured:'
        );
    }

    #[Test]
    public function theConfigurationIsInvalidIfNoPathIsSet(): void
    {
        $this->assertConfigurationIsInvalid(
            [
                [
                    'jwk_uris' => [
                        'foo' => [
                            'id' => 'foo',
                        ],
                    ],
                ],
            ],
            'The child config "path" under "jose.jwk_uris.foo" must be configured:'
        );
    }

    protected function getConfiguration(): Configuration
    {
        return new Configuration('jose', [new CoreSource(), new KeyManagementSource()]);
    }
}
