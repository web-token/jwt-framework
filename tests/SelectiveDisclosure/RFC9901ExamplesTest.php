<?php

declare(strict_types=1);

namespace Jose\Tests\SelectiveDisclosure;

use Jose\Component\Core\Util\JsonConverter;
use Jose\SelectiveDisclosure\Disclosable;
use Jose\SelectiveDisclosure\Disclosure;
use Jose\SelectiveDisclosure\SDJWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function count;
use function in_array;
use function is_array;
use function strlen;

/**
 * The examples of RFC 9901, sections 5 and 6 and appendix A.
 *
 * The Disclosures and their digests are reproduced byte for byte from the salts the RFC prints, and so is every
 * payload, up to the order of the object members. The Issuer-signed JWTs cannot be re-created, as the RFC only prints
 * the public key of appendix A.5: they are verified with it, and the Key Binding JWTs with the "cnf" key of the
 * examples.
 *
 * @internal
 */
final class RFC9901ExamplesTest extends SelectiveDisclosureTestCase
{
    #[Test]
    #[DataProvider('disclosures')]
    public function theDisclosureOfTheExampleIsParsedAndHashedAsPrinted(
        string $disclosure,
        string $digest,
        string $contents,
        ?string $claimName
    ): void {
        $parsed = Disclosure::fromString($disclosure);
        $array = JsonConverter::decode($contents);

        static::assertSame($digest, $parsed->digest('sha-256'));
        static::assertSame($disclosure, $parsed->toString());
        static::assertSame($array[0], $parsed->getSalt());
        static::assertSame($claimName, $parsed->getClaimName());
        static::assertSame($array[count($array) - 1], $parsed->getValue());
    }

    #[Test]
    #[DataProvider('disclosures')]
    public function theDisclosureOfTheExampleIsReproducedFromItsSalt(
        string $disclosure,
        string $digest,
        string $contents,
        ?string $claimName
    ): void {
        $array = JsonConverter::decode($contents);
        $reproduced = count($array) === 3
            ? Disclosure::forObjectProperty($array[1], $array[2], $array[0])
            : Disclosure::forArrayElement($array[1], $array[0]);

        static::assertSame($disclosure, $reproduced->toString());
        static::assertSame($digest, $reproduced->digest('sha-256'));
        static::assertSame($array[0], $reproduced->getSalt());
        static::assertSame($claimName, $reproduced->getClaimName());
        static::assertSame(count($array) === 2, $reproduced->isArrayElement());
    }

    /**
     * @return iterable<string, array{string, string, string, string|null}>
     */
    public static function disclosures(): iterable
    {
        foreach (self::exampleNames() as $name) {
            foreach (self::example($name)['disclosures'] as $index => $disclosure) {
                yield $name . ' #' . $index . ' ' . ($disclosure['claim'] ?? 'array element') => [
                    $disclosure['disclosure'],
                    $disclosure['digest'],
                    $disclosure['contents'],
                    $disclosure['claim'],
                ];
            }
        }
    }

    /**
     * Section 5.1, written out: the Issuer is given the claims, which of them are selectively disclosable and the salt
     * of each one. It produces the payload of the example and its Disclosures in the order the RFC prints them.
     */
    #[Test]
    public function theExampleOfSection5IsIssuedFromItsSalts(): void
    {
        $example = self::example('section-5');

        $sdJwt = self::issuer()->issue([
            'iss' => 'https://issuer.example.com',
            'iat' => 1683000000,
            'exp' => 1883000000,
            'sub' => 'user_42',
            'given_name' => new Disclosable('John', '2GLC42sKQveCfGfryNRN9w'),
            'family_name' => new Disclosable('Doe', 'eluV5Og3gSNII8EYnsxA_A'),
            'email' => new Disclosable('johndoe@example.com', '6Ij7tM-a5iVPGboS5tmvVA'),
            'phone_number' => new Disclosable('+1-202-555-0101', 'eI8ZWm9QnKPpNPeNenHdhQ'),
            'phone_number_verified' => new Disclosable(true, 'Qg_O64zqAxe412a108iroA'),
            'address' => new Disclosable([
                'street_address' => '123 Main St',
                'locality' => 'Anytown',
                'region' => 'Anystate',
                'country' => 'US',
            ], 'AJx-095VPrpTtN4QMOqROA'),
            'birthdate' => new Disclosable('1940-01-01', 'Pc33JM2LchcU_lHggv_ufQ'),
            'updated_at' => new Disclosable(1570000000, 'G02NSrQfjFXQ7Io09syajA'),
            'nationalities' => [
                new Disclosable('US', 'lklxF5jMYlGTPUovMNIvCA'),
                new Disclosable('DE', 'nPuoQnkRFq3BIeAm7AnXFA'),
            ],
            'cnf' => $example['payload']['cnf'],
        ], self::issuerKey(), [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ]);

        static::assertSame(self::canonical($example['payload']), self::canonical(self::payloadOf($sdJwt)));
        static::assertSame(
            substr((string) $example['sd_jwt'], strlen((string) $example['issuer_signed_jwt'])),
            substr($sdJwt->toString(), strlen($sdJwt->getIssuerSignedJwt())),
            'The Disclosures of the SD-JWT are those of section 5.1, in the same order.'
        );
    }

    #[Test]
    #[DataProvider('issuedExamples')]
    public function theIssuerReproducesThePayloadAndTheDisclosuresOfTheExample(string $name): void
    {
        $example = self::example($name);

        $sdJwt = self::issuer()->issue(self::markedClaims($example['marked_claims']), self::issuerKey(), [
            'alg' => 'ES256',
            'typ' => 'example+sd-jwt',
        ]);

        static::assertSame(
            self::canonical(self::withoutDigests($example['payload'], $example['decoys'] ?? [])),
            self::canonical(self::payloadOf($sdJwt))
        );
        static::assertSame(
            self::sorted(array_column($example['disclosures'], 'disclosure')),
            self::sorted(array_map(
                static fn (Disclosure $disclosure): string => $disclosure->toString(),
                $sdJwt->getDisclosures()
            ))
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function issuedExamples(): iterable
    {
        foreach (self::exampleNames() as $name) {
            yield $name => [$name];
        }
    }

    #[Test]
    #[DataProvider('presentations')]
    public function thePresentationOfTheExampleIsVerified(string $name): void
    {
        $example = self::example($name);
        $presentation = $example['presentation'];

        $verified = str_ends_with((string) $presentation, '~')
            ? self::verifier()->verify($presentation, self::rfcIssuerKey())
            : self::verifier()->verifyWithKeyBinding($presentation, self::rfcIssuerKey(), self::AUDIENCE, self::NONCE);

        static::assertSame(self::canonical($example['processed_payload']), self::canonical($verified->getClaims()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function presentations(): iterable
    {
        foreach (['section-5', 'appendix-a.1', 'appendix-a.2', 'appendix-a.3', 'appendix-a.4'] as $name) {
            yield $name => [$name];
        }
    }

    #[Test]
    #[DataProvider('issuedSdJwts')]
    public function theIssuedSdJwtOfTheExampleIsVerifiedWithAllItsDisclosures(string $name): void
    {
        $example = self::example($name);

        $verified = self::verifier()->verify($example['sd_jwt'], self::rfcIssuerKey());

        static::assertSame(
            self::canonical(self::withoutMarkers($example['marked_claims'])),
            self::canonical($verified->getClaims())
        );
        static::assertCount(count($example['disclosures']), $verified->getSdJwt()->getDisclosures());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function issuedSdJwts(): iterable
    {
        foreach (['section-5', 'appendix-a.3', 'appendix-a.4'] as $name) {
            yield $name => [$name];
        }
    }

    #[Test]
    public function theKeyBindingJwtsOfTheExamplesAreBoundToTheirPresentation(): void
    {
        static::assertSame(
            '0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY',
            SDJWT::fromString(self::example('section-5')['presentation'])->getSdHash()
        );
        static::assertSame(
            self::example('appendix-a.3')['key_binding_payload']['sd_hash'],
            SDJWT::fromString(self::example('appendix-a.3')['presentation'])->getSdHash()
        );
    }

    #[Test]
    public function theProcessedPayloadsCarryTheKeysOfTheExamples(): void
    {
        $verified = self::verifier()->verifyWithKeyBinding(
            self::example('section-5')['presentation'],
            self::rfcIssuerKey(),
            self::AUDIENCE,
            self::NONCE
        );

        static::assertTrue($verified->hasKeyBinding());
        static::assertSame(self::rfcIssuerKey()->all(), $verified->getIssuerKey()->all());
        static::assertSame(
            self::example('section-5')['payload']['cnf']['jwk'],
            $verified->getHolderKey()?->all()
        );
        static::assertSame(
            self::example('section-5')['key_binding_payload'],
            JsonConverter::decode((string) $verified->getKeyBindingJwt()?->getPayload())
        );
    }

    /**
     * The holder reproduces the choices of the presentations of the RFC: the claims it is asked to disclose bring the
     * Disclosures of the objects that contain them along, as in appendix A.2 and A.3.
     *
     * @param list<list<string|int|null>> $claimPaths
     */
    #[Test]
    #[DataProvider('selections')]
    public function theHolderSelectsTheDisclosuresOfThePresentationOfTheExample(string $name, array $claimPaths): void
    {
        $example = self::example($name);
        $presented = SDJWT::fromString($example['presentation'])->getDisclosures();

        $selected = SDJWT::fromString($example['sd_jwt'] ?? self::token(
            self::issuerSignedJwtOf($example['presentation']),
            array_column($example['disclosures'], 'disclosure')
        ))->select(...$claimPaths);

        static::assertSame(
            self::sorted(array_map(static fn (Disclosure $disclosure): string => $disclosure->toString(), $presented)),
            self::sorted(array_map(
                static fn (Disclosure $disclosure): string => $disclosure->toString(),
                $selected->getDisclosures()
            ))
        );
        static::assertFalse($selected->hasKeyBinding());
    }

    /**
     * @return iterable<string, array{string, list<list<string|int|null>>}>
     */
    public static function selections(): iterable
    {
        yield 'section-5' => ['section-5', [['given_name'], ['family_name'], ['address'], ['nationalities', 0]]];
        yield 'appendix-a.1' => ['appendix-a.1', [['address', 'region'], ['address', 'country']]];
        yield 'appendix-a.2' => ['appendix-a.2', [
            ['verified_claims', 'verification', 'time'],
            ['verified_claims', 'verification', 'evidence', 0, 'method'],
            ['verified_claims', 'claims', 'given_name'],
            ['verified_claims', 'claims', 'family_name'],
            ['verified_claims', 'claims', 'address'],
        ]];
        yield 'appendix-a.3' => ['appendix-a.3', [['age_equal_or_over', '18'], ['nationalities']]];
        yield 'appendix-a.4' => ['appendix-a.4', [
            ['credentialSubject', 'order'],
            ['credentialSubject', 'dateOfVaccination'],
            ['credentialSubject', 'vaccine', 'atcCode'],
            ['credentialSubject', 'vaccine', 'medicinalProductName'],
        ]];
    }

    /**
     * @return list<string>
     */
    private static function exampleNames(): array
    {
        return [
            'section-5',
            'section-6.1',
            'section-6.2',
            'section-6.3',
            'appendix-a.1',
            'appendix-a.2',
            'appendix-a.3',
            'appendix-a.4',
        ];
    }

    private static function issuerSignedJwtOf(string $token): string
    {
        return explode('~', $token, 2)[0];
    }

    /**
     * Removes the given digests from every "_sd" array: the decoy digests of appendix A.1 are random and cannot be
     * reproduced.
     *
     * @param list<string> $digests
     */
    private static function withoutDigests(mixed $value, array $digests): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        $result = [];
        foreach ($value as $name => $member) {
            if ($name === '_sd' && is_array($member)) {
                $member = array_values(array_filter(
                    $member,
                    static fn (mixed $digest): bool => ! in_array($digest, $digests, true)
                ));
            }
            $result[$name] = self::withoutDigests($member, $digests);
        }

        return $result;
    }

    private static function withoutMarkers(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        if (array_keys($value) === ['_selectively_disclosable']) {
            return self::withoutMarkers($value['_selectively_disclosable']['value']);
        }
        $result = [];
        foreach ($value as $name => $member) {
            $result[$name] = self::withoutMarkers($member);
        }

        return $result;
    }
}
