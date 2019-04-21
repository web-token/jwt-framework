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

namespace Jose\Component\Signature\Tests;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;

/**
 * @group ForeignJWT
 * @group Functional
 */
class ForeignJWTTest extends SignatureTest
{
    /*
     * The following test uses an assertion created with another library.
     * This assertion is valid if verified with the JWK.
     */

    /**
     * @test
     */
    public function validJWTFromOtherLibrary()
    {
        $jwk = new JWK([
            'kty' => 'RSA',
            'kid' => 'public',
            'n' => 'rYYOdiGrtRzCcV179qEI7TN-kkdmL37zJ3qugImaoOKbtw9EUwZGyMkcYp48eVksOwT7bxSn1hzP_n75Jlwl85MMAYIqKiQFHjjUVHBAD6HWFHsriod6-fdJxsXDhJ4lDoWxIQFLEKhGo3QeIYO0b6iwuSSIR2qO8sOCmmEngvq4OfyZz11mTpztl5cObeal8f6lQ5UHFUCXfx_QLnkrrTMuRioFZ1lEn2MhGm9Mx8eATY8OXUsK6L47LYP7aiWFKepesX4Tk16aKoB2GdlDO3-TG0aAYe89Ar7rGaoW39EYAuzxpbMka2Pp83Re4dEzMKMXy-mbGMTh5waqHIE9L9Rwldi2CaRrLgBBuMF_XyrCL4nMbEQ7xbVDxkayZ1sOir3TbrV9Z-bRjNNQhPl_zmfttyTEk18EyXhIwOVxjRmMdbPbP_K93o3h7_-mYTRgpoUM93X_3ec-lnyDHhSX2IrRe9z3eerzu4c7l3XV8eWhqIYWOw_AyArK1XxSlJhcSwWAFBXt7fYHGoT-wOI3lr7mJb8hqIMIOxA3M9-3NK_IPPjBcKQHrpUKQBulaYGCSlbIgUIkMDoxU4RaRAbR_31JLi9ZEgTmKjg7Db6I-omIlBSqdPZIEVQpHgGPlMMfKD05cYfXg82b5M_xuGNHXaFm_MkCJnKDq4NKx4ePUkM',
            'e' => 'AQAB',
        ]);

        $challenge = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJmNTIyMjI3OS1kNTQ0LTRjM2QtYWM3Yy1mYzU0NzE1ZDBjMjYiLCJleHAiOjE0Njk2NDkyMDksImp0aSI6IjZhZjExNDk3LTdkNmItNDQ5Ny04NDI1LTc0YmExM2E1ODMxYyIsInJlZGlyIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NDQ0NC9vYXV0aDIvYXV0aD9jbGllbnRfaWQ9ZjUyMjIyNzktZDU0NC00YzNkLWFjN2MtZmM1NDcxNWQwYzI2XHUwMDI2cmVzcG9uc2VfdHlwZT1jb2RlXHUwMDI2c2NvcGU9Y29yZStmb29cdTAwMjZzdGF0ZT1hYmNkZWZnaFx1MDAyNnJlZGlyZWN0X3VyaT1odHRwOi8vbG9jYWxob3N0L2NiIiwic2NwIjpbImNvcmUiLCJmb28iXX0.U3fu5eJVDD5tpOa9O3SejMh78skCj6a3rv5qWqzmME2WF0R9QnTR6TS5g6OOCh86o03AlHi2LhE4GSoUmC8WMPzXopDSdZdEkuifYUOSjRQV3Mp5tn6ozkkB75TtIhM8x5_QV3YKgTy3bcojg-Nx3ix43ENGdnbaCZ6Sxqj4xDknh7pHtsUiHfHZL7jd0I0xP5TYOw0_rxhuK9UZKtt_o05sFnNr0PW1k5d6aU5qJoBNVAendr_evrzXIV0yCC_odj5KySsNaQiXjUX_Tri2_5gSgcr8t3GMRm-HjDJRttwD3vgQG_K3vuToB-JAtHNMDcqmPjLzEFFkRDeh55kHgPJlYzSdwWD52b9sX5fj-VrRLdQzO2VVVkP7a9GoCGS06ypV9R_yGK8HzKJ8uB12dTNmplo03v4vdWxVdsnWxmBJ0m7G7yBCr-iGi87ezowpkMw22rNBkqnaEZIVbmX5E-G3UncE6io3IizEGH4YcGxWSk_D2fCII6X9uncf2rwslhEMiGC6rwlrL8dgl3kJTB4d0s2wIKgWJwEfLkiamJ2CJp6x0tqG7ozWv3k1tNQaZ9OwaulZ7nbmHgalyIOI2k-emMhFZsdnAtCxtcrxleevoiYF-Q54h1BhYInQT6Ejx7CdKOTEjljttB7lcqqpboSblw8Ji7lxUiKHWyGhcPI';

        $jwsVerifier = $this->getJWSVerifierFactory()->create(['RS256']);
        $jwt = $this->getJWSSerializerManager()->unserialize($challenge);
        static::assertTrue($jwsVerifier->verifyWithKey($jwt, $jwk, 0));

        $expectedHeader = [
            'alg' => 'RS256',
            'typ' => 'JWT',
        ];

        static::assertInstanceOf(JWS::class, $jwt);
        static::assertEquals($expectedHeader, $jwt->getSignature(0)->getProtectedHeader());
    }
}
