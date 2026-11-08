<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Encryption;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSS;
use Jose\Component\Encryption\JWE;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * A static key agreement only uses the two static keys, whichever of them is given as the private one.
 *
 * @internal
 */
final class ECDHSSStaticKeysTest extends EncryptionTestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    private const KEYS = [
        'P-256' => [
            'sender' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
                'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
                'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
            ],
            'recipient' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
                'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
                'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
            ],
            'third party' => [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
                'y' => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
                'd' => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
            ],
        ],
        'X25519' => [
            'sender' => [
                'kty' => 'OKP',
                'crv' => 'X25519',
                'x' => 'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo',
                'd' => 'dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo',
            ],
            'recipient' => [
                'kty' => 'OKP',
                'crv' => 'X25519',
                'x' => '3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08',
                'd' => 'XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os',
            ],
            'third party' => [
                'kty' => 'OKP',
                'crv' => 'X25519',
                'x' => 'EgTWq4kcecpV4e71xnEdMFIYF67Vtvq1CfevmAWtxSA',
                'd' => '-92XwNh9WRzVei8u5bA1LaUKVXOWnJIwFwxfrQz_rNk',
            ],
        ],
    ];

    #[Test]
    #[DataProvider('curves')]
    public function theAgreementKeyDoesNotDependOnTheEphemeralKeyOfTheHeader(string $crv): void
    {
        $ecdhss = new ECDHSS();
        $header = [
            'epk' => self::key($crv, 'third party')->toPublic()->all(),
        ];

        static::assertSame(
            $ecdhss->getAgreementKey(128, 'A128GCM', self::key($crv, 'recipient')->toPublic(), self::key($crv, 'sender')),
            $ecdhss->getAgreementKey(
                128,
                'A128GCM',
                self::key($crv, 'recipient'),
                self::key($crv, 'sender')->toPublic(),
                $header
            )
        );
    }

    #[Test]
    #[DataProvider('algorithmsAndCurves')]
    public function theTokenIsDecryptedWithThePrivateKeyOfTheRecipientAndThePublicKeyOfTheSender(
        string $alg,
        string $crv
    ): void {
        $jwe = $this->encrypt($alg, self::key($crv, 'sender'), self::key($crv, 'recipient'));

        static::assertSame(
            self::PAYLOAD,
            $this->decrypt($alg, $jwe, [self::key($crv, 'recipient')], self::key($crv, 'sender')->toPublic())
        );
    }

    #[Test]
    #[DataProvider('algorithmsAndCurves')]
    public function theTokenIsStillDecryptedWithThePublicKeyOfTheSenderAndThePrivateKeyOfTheRecipient(
        string $alg,
        string $crv
    ): void {
        $jwe = $this->encrypt($alg, self::key($crv, 'sender'), self::key($crv, 'recipient'));

        static::assertSame(
            self::PAYLOAD,
            $this->decrypt($alg, $jwe, [self::key($crv, 'sender')->toPublic()], self::key($crv, 'recipient'))
        );
    }

    #[Test]
    #[DataProvider('algorithmsAndCurves')]
    public function aTokenCarryingAnEphemeralKeyIsNotDecryptedWithThePrivateKeyOfTheRecipientAlone(
        string $alg,
        string $crv
    ): void {
        $thirdParty = self::key($crv, 'third party');
        $jwe = $this->encrypt($alg, $thirdParty, self::key($crv, 'recipient'), [
            'epk' => $thirdParty->toPublic()
                ->all(),
        ]);
        $keys = [self::key($crv, 'recipient'), self::key($crv, 'sender')->toPublic()];

        static::assertNull($this->decrypt($alg, $jwe, $keys, self::key($crv, 'recipient')));
        static::assertNull($this->decrypt($alg, $jwe, $keys, self::key($crv, 'sender')->toPublic()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function curves(): iterable
    {
        foreach (array_keys(self::KEYS) as $crv) {
            yield $crv => [$crv];
        }
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function algorithmsAndCurves(): iterable
    {
        foreach (['ECDH-SS', 'ECDH-SS+A128KW', 'ECDH-SS+A192KW', 'ECDH-SS+A256KW'] as $alg) {
            foreach (array_keys(self::KEYS) as $crv) {
                yield $alg . ', ' . $crv => [$alg, $crv];
            }
        }
    }

    private static function key(string $crv, string $owner): JWK
    {
        return new JWK(self::KEYS[$crv][$owner]);
    }

    /**
     * @param array<string, mixed> $header
     */
    private function encrypt(string $alg, JWK $senderKey, JWK $recipientKey, array $header = []): JWE
    {
        $jwe = $this->getJWEBuilderFactory()
            ->create([$alg, 'A128GCM'])
            ->create()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => $alg,
                'enc' => 'A128GCM',
            ] + $header)
            ->withSenderKey($senderKey)
            ->addRecipient($recipientKey->toPublic())
            ->build();
        $serializerManager = $this->getJWESerializerManager();

        return $serializerManager->unserialize($serializerManager->serialize('jwe_compact', $jwe, 0));
    }

    /**
     * @param JWK[] $keys
     */
    private function decrypt(string $alg, JWE $jwe, array $keys, JWK $senderKey): ?string
    {
        $jwk = null;
        $decrypted = $this->getJWEDecrypterFactory()
            ->create([$alg, 'A128GCM'])
            ->decryptUsingKeySet($jwe, new JWKSet($keys), 0, $jwk, $senderKey);

        return $decrypted ? $jwe->getPayload() : null;
    }
}
