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

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;

/**
 * Class RSAKeyWithoutAllPrimesTest.
 *
 * @group RSA2
 * @group unit
 *
 * @internal
 */
class RSAKeyWithoutAllPrimesTest extends EncryptionTest
{
    /**
     * @dataProvider dataEncryptionAlgorithms
     *
     * @test
     */
    public function encryptionAlgorithms(string $encryption_algorithm): void
    {
        $key = $this->getPrivateKey();

        $claims = JsonConverter::encode(['foo' => 'bar']);

        $jweBuilder = $this->getJWEBuilderFactory()->create([$encryption_algorithm], ['A256GCM'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create([$encryption_algorithm], ['A256GCM'], ['DEF']);

        $jwt = $jweBuilder
            ->create()->withPayload($claims)
            ->withSharedProtectedHeader(['alg' => $encryption_algorithm, 'enc' => 'A256GCM'])
            ->addRecipient($key)
            ->build()
        ;
        $jwt = $this->getJWESerializerManager()->serialize('jwe_compact', $jwt, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwt);

        static::assertTrue($jweDecrypter->decryptUsingKey($loaded, $key, 0));
    }

    /**
     * @dataProvider dataEncryptionAlgorithms
     *
     * @test
     */
    public function encryptionAlgorithmsWithMinimalRsaKey(string $encryption_algorithm): void
    {
        $key = $this->getMinimalPrivateKey();

        $claims = JsonConverter::encode(['foo' => 'bar']);

        $jweBuilder = $this->getJWEBuilderFactory()->create([$encryption_algorithm], ['A256GCM'], ['DEF']);
        $jweDecrypter = $this->getJWEDecrypterFactory()->create([$encryption_algorithm], ['A256GCM'], ['DEF']);

        $jwt = $jweBuilder
            ->create()->withPayload($claims)
            ->withSharedProtectedHeader(['alg' => $encryption_algorithm, 'enc' => 'A256GCM'])
            ->addRecipient($key)
            ->build()
        ;
        $jwt = $this->getJWESerializerManager()->serialize('jwe_compact', $jwt, 0);

        $loaded = $this->getJWESerializerManager()->unserialize($jwt);

        static::assertTrue($jweDecrypter->decryptUsingKey($loaded, $key, 0));
    }

    public function dataEncryptionAlgorithms(): array
    {
        return [
            ['RSA1_5'],
            ['RSA-OAEP'],
            ['RSA-OAEP-256'],
        ];
    }

    public function dataEncryptionAlgorithmsWithSimpleKey(): array
    {
        return [
            ['RSA-OAEP'],
            ['RSA-OAEP-256'],
        ];
    }

    private function getPrivateKey(): JWK
    {
        return new JWK(
            [
                'kty' => 'RSA',
                'kid' => 'private',
                'n' => '2NRPORHXd7wPU6atHqmSfWgEPvsP8HVUkY2AwQQAc8x1J509X5HFxeSXnQym9eAnZHl0JCPbvHoPH4QHlvITYoh0MSgFm2aOPyqOD-XcNdKWtnNX2JIurUCyVlwSwtlmy2ZbCz8YuUmFO0iacahfK1wbWT5QoY-pU3UxnMzDhlBslZN5uL7nRE8Sh_8BthsrMdYeGIMY55kh-P7xTs3MHzpOKhFSrOhdN6aO3HWYUuMAdoMNB-hJvckb2PbCy0_K1Wm3SBHtXn-cuMIUF00W9AR3amp3u3hLa2rcz29jEFXTr2FxKyLH4SdlnFFMJl2vaXuxM4PXgLN33Kj34PfKgc8ljDJ7oaSI9bKt7gunXOLv_o4XWYDq91cvUkOIDAsvqxzzHPZBt0Hru7roW3btkUOiqR6RWy-Cw272yiSEC5QA93m_vklD1KajoFeWN0BW2lWGlfGieZldvKX0sumk1TZuLhlHPHSKYcpeCfahT-jLr1yAeHql6qRN_a0BiHu-SSSjts6InmF1pAELznZ3Jn9-QXX78LsY3xaqOlYqHbCohxXorlYRi4so6eMGILtXjqHOoISb13Ez4YNOQmV4ygmyABRkE0AQG5KLy5cZB7LZn7zqw869UjXxWrmiOaBeDqOkxww6qiWIEDwPIouRLwOfPFtC4LGlb9LmG9Hlhp8',
                'e' => 'AQAB',
                'd' => 'PsMls2VAsz3SSepjDg8Tgg1LvVc6w-WSdxc4f6ZC40H5X2AaVcGCN8f1QtZYta8Od_zX62Ydwq6qFftHnx-vEMRirZ_iD5td7VbKDDwCw-mTCnjUorGdpTSm6mx4WcJICPQ1wkmfRHLNh916JxAPjCN7Hxf0iu9kme3AUJzMs-IvrBQmFZ3cn18sBAWCX0358NEDoSDBYrhmpwZUnvTe8uMToQWmoroX0XX6wEGht8xRY_yHFxTb032U-_ZhaCxOj_uru8bEqKfTm39CBYSg8j0gu8LZqYAmhI9IHxsk16OgRJG2CkBlDv0yYk799dUEY0oUfs7Y4D4SoeKe7ZWMHgKMEqa7ONz18ORznxqKSQhi4hfNVgwMzaM0IoYP4KOfHuaK263zhJU0hMzURJ8KifECeOsDHBR6BhLJ9TYzUe4c9UU55nFNgRBwknKHFFrRAsgVETEzmZWHzWwGQIFtKIAVZ1cjkdMEL3BlbzzXVofXfbbCrPQqcABYx2BZ-J_P8-UFjeMo83VLrR5IHj0_8IhQZUmxZYJcpTIwrf-1A4JGlN2_eLqRymF8tZI6zIPJyo1C0M1CIB3EeHzi-70SbF8xFtGUB7hR234yo_SM-KqVdIk2Sjjta2bQ1KXjSEcvrS_358AMiP0-9JT_fHxTCyzra-SNYoZhdnrEFzoVwQE',
                'p' => '6fWvnj34kJtfMnO1j-qbPjFnaTevREBGAypMvUBU3Fx1Xx0nE7zdc7lln2Qq5-yTQtOQ2lpiE69HkQLR4pMU6V44SjFgVzcTzbFCnNgknEV54S5dyp4KojSWxBi6bt5GwaACkiElDEw9wgc-8JgaEkv4F7e-w44HBwPDECTjE_N0vIawpbD_y6zpifB8ziaAI3xTG4ssA1dt8WZuyQW8SR4FRsYnfkqy0twwHn02gs7XSl4NepkhSO7CY5-YC3U6LazAEZi2NTiUuZSw7F6KaRhsA8CnXTDE5JqFks_fXfLNCbtClON2JtrB1zY-l-2bHyh2a6unDtGn9ZN-Ec7BXw',
                'q' => '7UF_NblAyTxmj7Z2Jz1sZmz-Q3YHOcta00DjmHBhR9ItYRMQFMj-SUGPAtwvN-sk3_ThugaQt46SLT_I3Gy8433cHdW7o3So6HiMYVunyfhqnWznSWs6SvIoEh8rJOXkkIZ-DlRP8XyW5OOvi0cbWEQ1f1jbFyistMmnBClPvf2TKKPvShUl9qmvLxuU87j-_bgQmjVmtwZadnPOyPAxQ4_qqSfIiTOvMSxSycr58rTyu3khHQapGHkS5-2Y_w40GUSfVJ3XP48delYpK-PZP71hn89MJTnnfPOtvJAk1wbEev5wQFTJd-PGOudkGkuEIXryF4TGxRPltl5UeF0CwQ',
            ]
        );
    }

    private function getMinimalPrivateKey(): JWK
    {
        return new JWK(
            [
                'd' => 'JSqz6ijkk3dfdSEA_0iMT_1HeIJ1ft4msZ6qw7_1JSCGQAALeZ1yM0QHO3uX-Jr7HC7v1rGVcwsonAhei2qu3rk-w_iCnRL6QkkMNBnDQycwaWpwGsMBFF-UqstOJNggE4AHX-aDnbd4wbKVvdX7ieehPngbPkHcJFdg_iSZCQNoajz6XfEruyIi7_IFXYEGmH_UyEbQkgNtriZysutgYdolUjo9flUlh20HbuV3NwsPjGyDG4dUMpNpdBpSuRHYKLX6h3FjeLhItBmhBfuL7d-G3EXwKlwfNXXYivqY5NQAkFNrRbvFlc_ARIws3zAfykPDIWGWFiPiN3H-hXMgAQ',
                'e' => 'AQAB',
                'n' => 'gVf-iyhwLn2J2Up4EKjwdLYmk5n24gjGk4oQkCHVcE7j8wkS1iSzcu0ApVcMPLklEp_PWycZE12vL90gPeVjF2IPL_MKFL0b6Wy7A1f4kCDkKv7TDDjt1IIwbS-Jdp-2pG7bPb3tWjJUu6QZBLoXfRtW3cMDkQjXaVGixENORLAZs6qdu2MMKV94jetCiFd0JYCjxGVC0HW2OKnM21B_2R1NubOvMlWA7gypdpvmBYDGpkw4mjV3walWlCZObG7IH84Ovl7wOP8XLzqi2un4e6fNzy3rdp4OUSPYItF4ZX5qThWYY2R47Z5sbrZxHjNeDECKUeio0KPQNrgr6FSKSw',
                'kty' => 'RSA',
                'kid' => 'test-key',
            ]
        );
    }
}
