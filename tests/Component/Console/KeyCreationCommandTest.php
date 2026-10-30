<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Console;

use InvalidArgumentException;
use Jose\Component\Console\EcKeyGeneratorCommand;
use Jose\Component\Console\MldsaKeyGeneratorCommand;
use Jose\Component\Console\MldsaKeysetGeneratorCommand;
use Jose\Component\Console\NoneKeyGeneratorCommand;
use Jose\Component\Console\OctKeyGeneratorCommand;
use Jose\Component\Console\OkpKeyGeneratorCommand;
use Jose\Component\Console\RsaKeyGeneratorCommand;
use Jose\Component\Console\SecretKeyGeneratorCommand;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\OKPKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use function sprintf;
use function strlen;

/**
 * @internal
 */
final class KeyCreationCommandTest extends TestCase
{
    #[Test]
    public function theEllipticCurveKeyCreationCommandIsAvailable(): void
    {
        $command = new EcKeyGeneratorCommand();

        static::assertTrue($command->isEnabled());
    }

    #[Test]
    public function theEllipticCurveKeyCreationCommandNeedTheCurveArgument(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[Test]
    public function iCannotCreateAnEllipticCurveKeyWithAnUnsupportedCurve(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The curve "P-128" is not supported.');

        $input = new ArrayInput([
            'curve' => 'P-128',
        ]);
        $output = new BufferedOutput();
        $command = new EcKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnEllipticCurveKeyWithCurveP256(): void
    {
        $input = new ArrayInput([
            'curve' => 'P-256',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new EcKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[Test]
    public function iCannotCreateAnOctetKeyWithoutKeySize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new OctKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnOctetKey(): void
    {
        $input = new ArrayInput([
            'size' => 256,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new OctKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[Test]
    public function iCanCreateAnOctetKeyUsingASecret(): void
    {
        $input = new ArrayInput([
            'secret' => 'This is my secret',
        ]);
        $output = new BufferedOutput();
        $command = new SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertTrue($jwk->has('k'));
        static::assertSame('This is my secret', Base64UrlSafe::decode($jwk->get('k')));
    }

    #[Test]
    public function iCanCreateAnOctetKeyUsingABinarySecret(): void
    {
        $secret = random_bytes(20);

        $input = new ArrayInput([
            'secret' => $secret,
            '--is_b64',
        ]);
        $output = new BufferedOutput();
        $command = new SecretKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        $jwk = JWK::createFromJson($content);
        static::assertTrue($jwk->has('k'));
        static::assertSame($secret, Base64UrlSafe::decode($jwk->get('k')));
    }

    #[Test]
    public function iCannotCreateAnOctetKeyPairWithoutKeyCurve(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "curve").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new OkpKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnOctetKeyPair(): void
    {
        $input = new ArrayInput([
            'curve' => 'X25519',
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new OkpKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function mldsaParameterSets(): iterable
    {
        yield 'ML-DSA-44' => ['ML-DSA-44', 1312];
        yield 'ML-DSA-65' => ['ML-DSA-65', 1952];
        yield 'ML-DSA-87' => ['ML-DSA-87', 2592];
    }

    #[Test]
    #[DataProvider('mldsaParameterSets')]
    public function iCanCreateAnMLDSAKey(string $algorithm, int $publicKeySize): void
    {
        if (! AKPKey::supportsOpenSSL()) {
            static::markTestSkipped('This platform has no ML-DSA: PHP 8.4 and an OpenSSL 3.5 runtime are required.');
        }
        $input = new ArrayInput([
            'algorithm' => $algorithm,
            '--use' => 'sig',
        ]);
        $output = new BufferedOutput();
        $command = new MldsaKeyGeneratorCommand();

        $command->run($input, $output);
        $jwk = JWK::createFromJson($output->fetch());

        static::assertSame('AKP', $jwk->get('kty'));
        static::assertSame($algorithm, $jwk->get('alg'));
        static::assertSame('sig', $jwk->get('use'));
        static::assertSame($publicKeySize, strlen(Base64UrlSafe::decodeNoPadding($jwk->getString('pub'))));
        static::assertSame(32, strlen(Base64UrlSafe::decodeNoPadding($jwk->getString('priv'))));
    }

    #[Test]
    public function iCanCreateAnMLDSAKeySet(): void
    {
        if (! AKPKey::supportsOpenSSL()) {
            static::markTestSkipped('This platform has no ML-DSA: PHP 8.4 and an OpenSSL 3.5 runtime are required.');
        }
        $input = new ArrayInput([
            'quantity' => 2,
            'algorithm' => 'ML-DSA-44',
        ]);
        $output = new BufferedOutput();
        $command = new MldsaKeysetGeneratorCommand();

        $command->run($input, $output);
        $jwkset = JWKSet::createFromJson($output->fetch());

        static::assertCount(2, $jwkset);
        foreach ($jwkset as $jwk) {
            static::assertSame('ML-DSA-44', $jwk->get('alg'));
        }
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function octetKeyPairCurves(): iterable
    {
        yield 'Ed25519' => ['Ed25519', 32];
        yield 'Ed448' => ['Ed448', 57];
        yield 'X25519' => ['X25519', 32];
        yield 'X448' => ['X448', 56];
    }

    #[Test]
    #[DataProvider('octetKeyPairCurves')]
    public function iCanCreateAnOctetKeyPairOnEveryCurve(string $curve, int $size): void
    {
        if (! OKPKey::isCurveSupported($curve)) {
            static::markTestSkipped(sprintf('The curve "%s" is not supported on this platform.', $curve));
        }
        $input = new ArrayInput([
            'curve' => $curve,
        ]);
        $output = new BufferedOutput();
        $command = new OkpKeyGeneratorCommand();

        $command->run($input, $output);
        $jwk = JWK::createFromJson($output->fetch());

        static::assertSame('OKP', $jwk->get('kty'));
        static::assertSame($curve, $jwk->get('crv'));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($jwk->getString('x'))));
        static::assertSame($size, strlen(Base64UrlSafe::decodeNoPadding($jwk->getString('d'))));
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateANoneKey(): void
    {
        $input = new ArrayInput([
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new NoneKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }

    #[Test]
    public function iCannotCreateAnRsaKeyWithoutKeySize(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not enough arguments (missing: "size").');

        $input = new ArrayInput([]);
        $output = new BufferedOutput();
        $command = new RsaKeyGeneratorCommand();

        $command->run($input, $output);
    }

    #[DoesNotPerformAssertions]
    #[Test]
    public function iCanCreateAnRsaKey(): void
    {
        $input = new ArrayInput([
            'size' => 2048,
            '--random_id' => true,
        ]);
        $output = new BufferedOutput();
        $command = new RsaKeyGeneratorCommand();

        $command->run($input, $output);
        $content = $output->fetch();
        JWK::createFromJson($content);
    }
}
