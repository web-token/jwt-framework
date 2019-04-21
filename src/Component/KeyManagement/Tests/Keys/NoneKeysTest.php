<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\KeyManagement\Tests\Keys;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

/**
 * @group NoneKeys
 * @group Unit
 */
class NoneKeysTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7638#section-3.1
     *
     * @test
     */
    public function keyThumbprint()
    {
        $key = new JWK([
            'kty' => 'none',
            'alg' => 'none',
            'use' => 'sig',
            'kid' => '2011-04-29',
        ]);

        static::assertEquals('{"kty":"none","alg":"none","use":"sig","kid":"2011-04-29"}', \json_encode($key));
        static::assertEquals('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        static::assertEquals('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        static::assertEquals('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }

    /**
     * @test
     */
    public function createNoneKey()
    {
        $key = JWKFactory::createNoneKey(['kid' => 'NONE_KEY']);

        static::assertEquals('none', $key->get('kty'));
        static::assertEquals('none', $key->get('alg'));
        static::assertEquals('sig', $key->get('use'));
        static::assertEquals('NONE_KEY', $key->get('kid'));

        static::assertEquals('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        static::assertEquals('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        static::assertEquals('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }
}
