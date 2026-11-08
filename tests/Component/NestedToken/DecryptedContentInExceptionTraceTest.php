<?php

declare(strict_types=1);

namespace Jose\Tests\Component\NestedToken;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Tests\Component\Core\ExceptionTraceArgumentsTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * When the inner JWS of a nested token is refused, the arguments recorded in the traces of the exception chain must
 * not hold what the library decrypted: the inner token, its claims or its signing input. Genuine tokens are refused
 * this way, for instance once the issuer has rotated its signing key.
 *
 * The signature keys are the ones of RFC 7515 appendix A and RFC 7517 appendix A.1.
 *
 * @internal
 */
final class DecryptedContentInExceptionTraceTest extends TestCase
{
    use ExceptionTraceArgumentsTrait;

    private const CLAIMS = '{"sub":"alice","confidential":"known to the issuer and to the recipient only"}';

    private const ENCRYPTION_KEY = 'kek-A128KW-01234';

    private const RSA_SIGNING_KEY = [
        'kty' => 'RSA',
        'n' => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
        'e' => 'AQAB',
        'd' => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
        'p' => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
        'q' => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
        'dp' => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
        'dq' => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
        'qi' => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
    ];

    private const ROTATED_RSA_KEY = [
        'kty' => 'RSA',
        'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
        'e' => 'AQAB',
    ];

    private const EC_SIGNING_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
    ];

    private const MAC_KEY = [
        'kty' => 'oct',
        'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
    ];

    #[Test]
    #[DataProvider('refusedContents')]
    public function theDecryptedContentIsNotAmongTheRecordedArguments(string $content): void
    {
        $token = self::encrypt($content);

        $exception = self::failureOf(static fn (): JWS => self::loader()->load(
            $token,
            new JWKSet([self::encryptionKey()]),
            new JWKSet([new JWK(self::ROTATED_RSA_KEY)])
        ));

        static::assertNotSame([], self::callsHolding($exception, $token), 'The arguments are not recorded.');
        static::assertSame([
            'content' => [],
            'claims' => [],
        ], [
            'content' => self::callsHolding($exception, $content),
            'claims' => self::callsHolding($exception, Base64UrlSafe::encodeUnpadded(self::CLAIMS)),
        ]);
    }

    #[Test]
    public function theNestedTokenIsAcceptedWithTheSigningKey(): void
    {
        $token = self::encrypt(self::sign('PS256', new JWK(self::RSA_SIGNING_KEY), new CompactSerializer()));

        $jws = self::loader()->load(
            $token,
            new JWKSet([self::encryptionKey()]),
            new JWKSet([(new JWK(self::RSA_SIGNING_KEY))->toPublic()])
        );

        static::assertSame(self::CLAIMS, $jws->getPayload());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function refusedContents(): iterable
    {
        $rsaKey = new JWK(self::RSA_SIGNING_KEY);
        yield 'PS256, compact' => [self::sign('PS256', $rsaKey, new CompactSerializer())];
        yield 'PS256, JSON flattened' => [self::sign('PS256', $rsaKey, new JSONFlattenedSerializer())];
        yield 'PS256, JSON general' => [self::sign('PS256', $rsaKey, new JSONGeneralSerializer())];
        yield 'RS256, compact' => [self::sign('RS256', $rsaKey, new CompactSerializer())];
        yield 'ES256 against an RSA key' => [self::sign('ES256', new JWK(self::EC_SIGNING_KEY), new CompactSerializer())];
        yield 'HS256 against an RSA key' => [self::sign('HS256', new JWK(self::MAC_KEY), new CompactSerializer())];
        yield 'neither JSON nor a JWS' => ['known to the issuer and to the recipient only'];
    }

    private static function sign(string $algorithm, JWK $key, JWSSerializer $serializer): string
    {
        $jws = (new JWSBuilder(self::signatureAlgorithms()))
            ->create()
            ->withPayload(self::CLAIMS)
            ->addSignature($key, [
                'alg' => $algorithm,
            ])
            ->build();

        return $serializer->serialize($jws, 0);
    }

    private static function encrypt(string $content): string
    {
        $jwe = (new JWEBuilder(new AlgorithmManager([new A128KW(), new A128GCM()])))
            ->create()
            ->withPayload($content)
            ->withSharedProtectedHeader([
                'alg' => 'A128KW',
                'enc' => 'A128GCM',
                'cty' => 'JWT',
            ])
            ->addRecipient(self::encryptionKey())
            ->build();

        return (new JWECompactSerializer())->serialize($jwe, 0);
    }

    private static function loader(): NestedTokenLoader
    {
        return new NestedTokenLoader(
            new JWELoader(
                new JWESerializerManager([new JWECompactSerializer()]),
                new JWEDecrypter(new AlgorithmManager([new A128KW(), new A128GCM()])),
                null
            ),
            new JWSLoader(
                new JWSSerializerManager([
                    new CompactSerializer(),
                    new JSONFlattenedSerializer(),
                    new JSONGeneralSerializer(),
                ]),
                new JWSVerifier(self::signatureAlgorithms()),
                null
            )
        );
    }

    private static function signatureAlgorithms(): AlgorithmManager
    {
        return new AlgorithmManager([new PS256(), new RS256(), new ES256(), new HS256()]);
    }

    private static function encryptionKey(): JWK
    {
        return new JWK([
            'kty' => 'oct',
            'k' => Base64UrlSafe::encodeUnpadded(self::ENCRYPTION_KEY),
        ]);
    }
}
