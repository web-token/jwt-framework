<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Tests\Component\Encryption;

use Exception;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWELoader;

/**
 * Class JWELoaderTest.
 *
 * @group JWELoader
 * @group functional
 *
 * @internal
 */
class JWELoaderTest extends EncryptionTest
{
    /**
     * @var null|JWELoader
     */
    private $jweLoader;

    /**
     * @test
     */
    public function theFlattenedTokenCannotBeLoaded(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unable to load and decrypt the token.');

        $token = '{"protected":"eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx","iv":"Qx0pmsDa8KnJc9Jo","ciphertext":"AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF","tag":"ER7MWJZ1FBI_NKvn7Zb1Lw"}';
        $key = new JWK([
            'kty' => 'EC',
            'kid' => 'peregrin.took@tuckborough.example',
            'use' => 'enc',
            'crv' => 'P-384',
            'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
            'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
        ]);

        $this->getJWELoader()->loadAndDecryptWithKey($token, $key, $recipient);
    }

    /**
     * @test
     */
    public function theTokenCannotBeVerifiedBecauseOfAnUnsupportedAlgorithm(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unable to load and decrypt the token.');

        $token = 'eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0.0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2.mH-G2zVqgztUtnW_.tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ.WuGzxmcreYjpHGJoa17EBg';
        $key = new JWK([
            'kty' => 'EC',
            'kid' => 'peregrin.took@tuckborough.example',
            'use' => 'enc',
            'crv' => 'P-384',
            'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
            'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
        ]);

        $this->getJWELoader()->loadAndDecryptWithKey($token, $key, $recipient);
    }

    /**
     * @test
     */
    public function theTokenCannotBeVerifiedBecauseOfABadKey(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unable to load and decrypt the token.');

        $token = 'eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx.Qx0pmsDa8KnJc9Jo.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.ER7MWJZ1FBI_NKvn7Zb1Lw';
        $key = new JWK([
            'kty' => 'EC',
            'kid' => 'peregrin.took@tuckborough.example',
            'use' => 'enc',
            'crv' => 'P-384',
            'x' => 'YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2',
            'y' => 'A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP',
        ]);

        $this->getJWELoader()->loadAndDecryptWithKey($token, $key, $recipient);
    }

    /**
     * @test
     */
    public function theJweLoaderCanLoadAndDecryptAToken(): void
    {
        $token = 'eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx.Qx0pmsDa8KnJc9Jo.AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.ER7MWJZ1FBI_NKvn7Zb1Lw';
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);
        $recipient = 0;
        $jwe = $this->getJWELoader()->loadAndDecryptWithKey($token, $key, $recipient);

        static::assertEquals('You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.', $jwe->getPayload());
        static::assertEquals(0, $recipient);
    }

    private function getJWELoader(): JWELoader
    {
        if (null === $this->jweLoader) {
            $this->jweLoader = $this->getJWELoaderFactory()->create(['jwe_compact'], ['A128KW'], ['A128GCM'], ['DEF']);
        }

        return $this->jweLoader;
    }
}
