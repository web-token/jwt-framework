<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\JWKFactoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use const E_USER_DEPRECATED;

/**
 * The key factory is a service: it can be injected through its interface, decorated and unit tested. The static
 * methods it used to expose are kept as delegations to a default instance and are deprecated.
 *
 * @internal
 */
final class JWKFactoryServiceTest extends TestCase
{
    #[Test]
    public function theFactoryImplementsItsInterface(): void
    {
        static::assertInstanceOf(JWKFactoryInterface::class, new JWKFactory());
    }

    #[Test]
    public function usingTheServiceIsNotDeprecated(): void
    {
        $key = null;
        $deprecations = $this->collectDeprecations(static function () use (&$key): void {
            $key = (new JWKFactory())->fromSecret('This is a very secured secret!!!!');
        });

        static::assertSame([], $deprecations);
        static::assertInstanceOf(JWK::class, $key);
        static::assertSame('oct', $key->get('kty'));
    }

    #[Test]
    #[DataProvider('deprecatedStaticMethods')]
    public function theStaticMethodsAreDeprecatedAndKeepWorking(
        string $static,
        string $replacement,
        callable $call
    ): void {
        $result = null;
        $deprecations = $this->collectDeprecations(static function () use ($call, &$result): void {
            $result = $call();
        });

        static::assertCount(1, $deprecations);
        static::assertStringContainsString(
            sprintf('The method "%s::%s()" is deprecated', JWKFactory::class, $static),
            $deprecations[0]
        );
        static::assertStringContainsString(sprintf('call "%s()" instead', $replacement), $deprecations[0]);
        static::assertTrue($result instanceof JWK || $result instanceof JWKSet);
    }

    /**
     * @return iterable<string, array{string, string, callable}>
     */
    public static function deprecatedStaticMethods(): iterable
    {
        yield 'createOctKey' => [
            'createOctKey',
            'oct',
            static fn (): JWK => JWKFactory::createOctKey(128),
        ];
        yield 'createNoneKey' => [
            'createNoneKey',
            'none',
            JWKFactory::createNoneKey(...),
        ];
        yield 'createECKey' => [
            'createECKey',
            'ec',
            static fn (): JWK => JWKFactory::createECKey('P-256'),
        ];
        yield 'createFromSecret' => [
            'createFromSecret',
            'fromSecret',
            static fn (): JWK => JWKFactory::createFromSecret('This is a very secured secret!!!!'),
        ];
        yield 'createFromValues' => [
            'createFromValues',
            'fromValues',
            static fn (): JWK|JWKSet => JWKFactory::createFromValues([
                'kty' => 'oct',
                'k' => 'GawgguFyGrWKav7AX4VKUg',
            ]),
        ];
        yield 'createFromJsonObject' => [
            'createFromJsonObject',
            'fromJsonObject',
            static fn (): JWK|JWKSet => JWKFactory::createFromJsonObject('{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}'),
        ];
    }

    /**
     * @param callable(): void $callback
     *
     * @return list<string>
     */
    private function collectDeprecations(callable $callback): array
    {
        $deprecations = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$deprecations): bool {
            $deprecations[] = $errstr;

            return true;
        }, E_USER_DEPRECATED);

        try {
            $callback();
        } finally {
            restore_error_handler();
        }

        return $deprecations;
    }
}
