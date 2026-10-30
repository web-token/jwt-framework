<?php

declare(strict_types=1);

namespace Jose\Tests\Bundle\JoseFramework\Functional\KeyManagement;

use Jose\Bundle\JoseFramework\DataCollector\JoseCollector;
use Jose\Bundle\JoseFramework\DataCollector\KeyCollector;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Tests\Bundle\JoseFramework\ProfilerKernel;
use Jose\Tests\Bundle\JoseFramework\WebTestCase;
use JsonException;
use Override;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Profiler\Profile;
use Symfony\Component\HttpKernel\Profiler\Profiler;
use function array_keys;

/**
 * The application configured in ProfilerKernel declares keys and key sets that cannot be loaded or analyzed. The
 * requests below never use them, so the application works as long as the profiler does not touch them either.
 *
 * @internal
 */
final class KeyCollectorTest extends WebTestCase
{
    #[Test]
    public function aKeyThatCannotBeLoadedDoesNotBreakTheRequest(): void
    {
        $client = static::createClient();
        $client->request('GET', '/keys/valid.jwkset');

        static::assertResponseIsSuccessful();
    }

    #[Test]
    public function theProfilerDoesNotCreateTheKeysWhenItDoesNotCollect(): void
    {
        $client = static::createClient();
        $client->request('GET', '/keys/valid.jwkset');

        static::assertResponseIsSuccessful();
        $container = static::getContainer();
        static::assertInstanceOf(Profiler::class, $container->get('profiler'));
        static::assertTrue($container->initialized('jose.key_set.valid'));
        static::assertFalse($container->initialized('jose.key.valid'));
    }

    #[Test]
    public function theProfilerReportsTheKeysThatCannotBeLoaded(): void
    {
        $client = static::createClient();
        $client->enableProfiler();
        $client->request('GET', '/keys/valid.jwkset');

        static::assertResponseIsSuccessful();
        $profile = $client->getProfile();
        static::assertInstanceOf(Profile::class, $profile);
        $collector = $profile->getCollector('jose_collector');
        static::assertInstanceOf(JoseCollector::class, $collector);
        $data = $collector->getData();
        static::assertIsArray($data);

        $jwks = $data['key']['jwk'];
        static::assertSame(
            ['jose.key.valid', 'jose.key.empty_value', 'jose.key.without_secret'],
            array_keys($jwks)
        );
        static::assertArrayHasKey('jwk', $jwks['jose.key.valid']);
        static::assertArrayHasKey('analyze', $jwks['jose.key.valid']);
        static::assertArrayNotHasKey('error', $jwks['jose.key.valid']);
        static::assertSame([
            'class' => JsonException::class,
            'message' => 'Syntax error',
        ], $jwks['jose.key.empty_value']['error']);
        static::assertSame(
            'The value identified by "k" does not exist.',
            $jwks['jose.key.without_secret']['error']['message']
        );

        $jwksets = $data['key']['jwkset'];
        static::assertSame(['jose.key_set.valid', 'jose.key_set.empty_value'], array_keys($jwksets));
        static::assertArrayHasKey('jwkset', $jwksets['jose.key_set.valid']);
        static::assertArrayHasKey('analyze', $jwksets['jose.key_set.valid']);
        static::assertArrayHasKey('analyze_jwkset', $jwksets['jose.key_set.valid']);
        static::assertArrayNotHasKey('error', $jwksets['jose.key_set.valid']);
        static::assertSame([
            'class' => JsonException::class,
            'message' => 'Syntax error',
        ], $jwksets['jose.key_set.empty_value']['error']);
    }

    #[Test]
    public function keysAddedAsObjectsAreStillCollected(): void
    {
        $jwk = new JWK([
            'kty' => 'oct',
            'k' => 'dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbE',
        ]);
        $keyCollector = new KeyCollector();
        $keyCollector->addJWK('jwk1', $jwk);
        $keyCollector->addJWKSet('jwkset1', new JWKSet([$jwk]));

        $data = [];
        $keyCollector->collect($data, new Request(), new Response());

        static::assertSame(['jwk1'], array_keys($data['key']['jwk']));
        static::assertArrayHasKey('jwk', $data['key']['jwk']['jwk1']);
        static::assertSame(['jwkset1'], array_keys($data['key']['jwkset']));
        static::assertArrayHasKey('jwkset', $data['key']['jwkset']['jwkset1']);
    }

    #[Override]
    protected static function getKernelClass(): string
    {
        return ProfilerKernel::class;
    }
}
