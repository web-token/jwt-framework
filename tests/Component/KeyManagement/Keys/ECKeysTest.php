<?php

declare(strict_types=1);

namespace Jose\Tests\Component\KeyManagement\Keys;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\KeyManagement\KeyConverter\KeyConverter;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use const DIRECTORY_SEPARATOR;

/**
 * @internal
 */
final class ECKeysTest extends TestCase
{
    #[Test]
    public function keyTypeNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key type');

        $file = 'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'DSA' . DIRECTORY_SEPARATOR . 'DSA.key';
        KeyConverter::loadFromKeyFile($file);
    }

    /**
     * @see https://github.com/Spomky-Labs/jose/issues/141
     * @see https://gist.github.com/Spomky/246eca6aaeeb7a40f11d3a2d98960282
     */
    #[Test]
    public function loadPrivateEC256KeyGenerateByAPN(): void
    {
        $pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es256.from.APN.key'
        );
        $details = KeyConverter::loadFromKey($pem);
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => '13n3isfsEktzl-CtH5ECpRrKk-40prVuCbldkP77gak',
            'x' => 'YcIMUkalwbeeAVkUF6FP3aBVlCzlqxEd7i0uN_4roA0',
            'y' => 'bU8wOWJBkTNZ61gB1_4xp-r8-uVsQB8D6Xsl-aKMCy8',
        ]);
    }

    #[Test]
    public function loadPublicEC256Key(): void
    {
        $pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'public.es256.key'
        );
        $details = KeyConverter::loadFromKey($pem);
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);
    }

    #[Test]
    public function loadPrivateEC256Key(): void
    {
        // Given
        $private_pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es256.key'
        );
        $expectedValues = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ];

        // Whent
        $details = KeyConverter::loadFromKey($private_pem, 'test');

        //Then
        static::assertSame($details, $expectedValues);
        $ecKey = ECKey::convertPrivateKeyToPEM(new JWK($expectedValues));
        static::assertSame($private_pem, $ecKey);
    }

    #[Test]
    public function loadEncryptedPrivateEC256Key(): void
    {
        $private_pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es256.encrypted.key'
        );
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);
    }

    #[Test]
    public function loadEncryptedPrivateEC256KeyWithoutPassword(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Password required for encrypted keys.');

        KeyConverter::loadFromKeyFile(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es256.encrypted.key'
        );
    }

    #[Test]
    public function loadPublicEC384Key(): void
    {
        $pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'public.es384.key'
        );
        $details = KeyConverter::loadFromKey($pem);
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
    }

    #[Test]
    public function loadPrivateEC384Key(): void
    {
        $private_pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es384.key'
        );
        $details = KeyConverter::loadFromKey($private_pem);
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
    }

    #[Test]
    public function loadEncryptedPrivateEC384Key(): void
    {
        $private_pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es384.encrypted.key'
        );
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
    }

    #[Test]
    public function loadPublicEC512Key(): void
    {
        $pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'public.es512.key'
        );
        $details = KeyConverter::loadFromKey($pem);
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);
    }

    #[Test]
    public function loadPrivateEC512Key(): void
    {
        $private_pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es512.key'
        );
        $details = KeyConverter::loadFromKey($private_pem);
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);
    }

    #[Test]
    public function loadEncryptedPrivateEC512Key(): void
    {
        $private_pem = file_get_contents(
            'file://' . __DIR__ . DIRECTORY_SEPARATOR . 'EC' . DIRECTORY_SEPARATOR . 'private.es512.encrypted.key'
        );
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        static::assertSame($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);
    }

    #[Test]
    public function loadInvalidPEMKey(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unable to load the key');

        // Given
        $private_pem = trim(<<<PEM
MIIB0jCCAXegAwIBAgIJAK2o1kQ5JwpUMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTUxMTA4MTUxMTU2WhcNMTYxMTA3MTUxMTU2WjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExEsr
/55aqgFXdrbRNz1/WSNI8UaSUxCka2kGEN1bXsJIzjkeyv12dRHo7H5OmY2/Z9sN
fgKhWj7elq0xSlcA0KNQME4wHQYDVR0OBBYEFKIGgCZoS388STT0qjoX/swKYBXh
MB8GA1UdIwQYMBaAFKIGgCZoS388STT0qjoX/swKYBXhMAwGA1UdEwQFMAMBAf8w
CgYIKoZIzj0EAwIDSQAwRgIhAK5OqQoBGR/pj2NOb+PyRKK4k4d3Muj9z/6LsJK+
kkgUAiEA+FY4SWKv4mfe0gsOBId0Aah/HtVZxDBe3bCXOQM8MMM=
PEM);

        // When
        KeyConverter::loadFromKey($private_pem, 'test');
    }

    #[Test]
    public function convertPrivateKeyToPublic(): void
    {
        $jwk = new JWK([
            'kty' => 'EC',
            'kid' => 'Foo',
            'crv' => 'P-256',
            'use' => 'sig',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
            'foo' => 'bar',
        ]);

        static::assertSame([
            'kty' => 'EC',
            'kid' => 'Foo',
            'crv' => 'P-256',
            'use' => 'sig',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
            'foo' => 'bar',
        ], $jwk->toPublic()
            ->all());
    }

    #[Test]
    public function createECKeyOnP256(): void
    {
        $jwk = JWKFactory::createECKey('P-256');

        static::assertSame('EC', $jwk->get('kty'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('y'));
    }

    #[Test]
    public function createECKeyOnP384(): void
    {
        $jwk = JWKFactory::createECKey('P-384');

        static::assertSame('EC', $jwk->get('kty'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('y'));
    }

    #[Test]
    public function createECKeyOnP521(): void
    {
        $jwk = JWKFactory::createECKey('P-521');

        static::assertSame('EC', $jwk->get('kty'));
        static::assertTrue($jwk->has('d'));
        static::assertTrue($jwk->has('x'));
        static::assertTrue($jwk->has('y'));
    }
}
