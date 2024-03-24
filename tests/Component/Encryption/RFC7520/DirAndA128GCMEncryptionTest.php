<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption\RFC7520;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Tests\Component\Encryption\EncryptionTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.6
 *
 * @internal
 */
final class DirAndA128GCMEncryptionTest extends EncryptionTestCase
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are
     * always different). The output given in the RFC is used and only decrypted.
     */
    #[Test]
    public function dirAndA128GCMEncryption(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
            'use' => 'enc',
            'alg' => 'A128GCM',
            'k' => 'XctOhJAkA-pD9Lh7ZgW_2A',
        ]);

        $protectedHeader = [
            'alg' => 'dir',
            'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
            'enc' => 'A128GCM',
        ];

        $expected_compact_json = 'eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0..refa467QzzKx6QAB.JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp.vbb32Xvllea2OtmHAdccRQ';
        $expected_json = '{"protected":"eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0","iv":"refa467QzzKx6QAB","ciphertext":"JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp","tag":"vbb32Xvllea2OtmHAdccRQ"}';
        $expected_iv = 'refa467QzzKx6QAB';
        $expected_ciphertext = 'JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp';
        $expected_tag = 'vbb32Xvllea2OtmHAdccRQ';

        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['dir', 'A128GCM']);

        $loaded_compact_json = $this->getJWESerializerManager()
            ->unserialize($expected_compact_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()
            ->unserialize($expected_json);
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertSame($expected_ciphertext, Base64UrlSafe::encodeUnpadded($loaded_compact_json->getCiphertext()));
        static::assertSame($protectedHeader, $loaded_compact_json->getSharedProtectedHeader());
        static::assertSame($expected_iv, Base64UrlSafe::encodeUnpadded($loaded_compact_json->getIV()));
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_compact_json->getTag()));

        static::assertSame($expected_ciphertext, Base64UrlSafe::encodeUnpadded($loaded_json->getCiphertext()));
        static::assertSame($protectedHeader, $loaded_json->getSharedProtectedHeader());
        static::assertSame($expected_iv, Base64UrlSafe::encodeUnpadded($loaded_json->getIV()));
        static::assertSame($expected_tag, Base64UrlSafe::encodeUnpadded($loaded_json->getTag()));

        static::assertSame($expected_payload, $loaded_compact_json->getPayload());
        static::assertSame($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     */
    #[Test]
    public function dirAndA128GCMEncryptionBis(): void
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
            'use' => 'enc',
            'alg' => 'A128GCM',
            'k' => 'XctOhJAkA-pD9Lh7ZgW_2A',
        ]);

        $protectedHeader = [
            'alg' => 'dir',
            'kid' => '77c7e2b8-6e13-45cf-8672-617b5b45243a',
            'enc' => 'A128GCM',
        ];

        $jweBuilder = $this->getJWEBuilderFactory()
            ->create(['dir', 'A128GCM']);
        $jweDecrypter = $this->getJWEDecrypterFactory()
            ->create(['dir', 'A128GCM']);

        $jwe = $jweBuilder
            ->create()
            ->withPayload($expected_payload)
            ->withSharedProtectedHeader($protectedHeader)
            ->addRecipient($private_key)
            ->build();

        $loaded_compact_json = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_compact', $jwe, 0));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_compact_json, $private_key, 0));

        $loaded_json = $this->getJWESerializerManager()
            ->unserialize($this->getJWESerializerManager()->serialize('jwe_json_general', $jwe));
        static::assertTrue($jweDecrypter->decryptUsingKey($loaded_json, $private_key, 0));

        static::assertSame($protectedHeader, $loaded_compact_json->getSharedProtectedHeader());

        static::assertSame($protectedHeader, $loaded_json->getSharedProtectedHeader());

        static::assertSame($expected_payload, $loaded_compact_json->getPayload());
        static::assertSame($expected_payload, $loaded_json->getPayload());
    }
}
