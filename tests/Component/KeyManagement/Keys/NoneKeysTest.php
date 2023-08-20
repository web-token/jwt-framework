<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement\Keys;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 */
final class NoneKeysTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7638#section-3.1
     */
    #[Test]
    public function keyThumbprint(): void
    {
        $key = new JWK([
            'kty' => 'none',
            'alg' => 'none',
            'use' => 'sig',
            'kid' => '2011-04-29',
        ]);

        static::assertSame(
            '{"kty":"none","alg":"none","use":"sig","kid":"2011-04-29"}',
            json_encode($key, JSON_THROW_ON_ERROR)
        );
        static::assertSame('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        static::assertSame('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        static::assertSame('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }

    #[Test]
    public function createNoneKey(): void
    {
        $key = JWKFactory::createNoneKey([
            'kid' => 'NONE_KEY',
        ]);

        static::assertSame('none', $key->get('kty'));
        static::assertSame('none', $key->get('alg'));
        static::assertSame('sig', $key->get('use'));
        static::assertSame('NONE_KEY', $key->get('kid'));

        static::assertSame('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        static::assertSame('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        static::assertSame('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }
}
