<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\NamedInformationHash;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilderInterface;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Override;
use function array_is_list;
use function array_key_exists;
use function array_map;
use function array_splice;
use function array_unique;
use function count;
use function in_array;
use function is_array;
use function is_string;
use function random_bytes;
use function random_int;
use function sort;
use function sprintf;
use const SORT_STRING;

/**
 * Issues SD-JWTs, as RFC 9901 sections 4.1 and 4.2 describe.
 *
 * The claims are walked in their order. Each Disclosable becomes a Disclosure, created after the Disclosures its value
 * contains, and is replaced by its digest: in the "_sd" array of its object, or by a {"...": digest} element at its
 * position in its array. The "_sd" array is placed first in its object and sorted, which hides the original order of
 * the claims (section 4.2.4.1). The Disclosures are returned in the order they are created.
 *
 * Decoy digests (section 4.2.5) are added to every "_sd" array and to every array that has a selectively disclosable
 * element: a number of them drawn between the given bounds, each the digest of 128 random bits, at random positions
 * in the arrays. They have the length of the real digests and the sort of the "_sd" arrays mixes them with the real
 * ones. Objects and arrays without selectively disclosable claims are left untouched, so that the claims a Verifier
 * expects in clear, such as "cnf", keep their shape.
 *
 * The claim names "_sd", "..." and "_sd_alg" are reserved (section 4.1). The claims "iss", "aud", "exp", "nbf" and
 * "cnf" of the top level, which control the validity of the SD-JWT (section 9.7), cannot be selectively disclosable;
 * the elements of "aud" can.
 *
 * The SD-JWT is issued in the compact format by issue(), and in the JWS JSON serialization of section 8 by
 * issueJson(): the Issuer-signed JWT is then serialized by the JSON serializer of the library, flattened when it has
 * one signature and general when it has several, and the Disclosures are carried by the "disclosures" parameter of the
 * unprotected header of the first signature. The unprotected headers cannot have the "disclosures" and "kb_jwt"
 * parameters themselves.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-4
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-8
 */
final readonly class SDJWTIssuer implements SDJWTIssuerInterface
{
    private const RESERVED_CLAIM_NAMES = ['_sd', '...', '_sd_alg'];

    private const VALIDITY_CLAIMS = ['iss', 'aud', 'exp', 'nbf', 'cnf'];

    /**
     * The parameters of the unprotected header that carry the Disclosures and the Key Binding JWT in the JWS JSON
     * serialization (section 8.1).
     */
    private const RESERVED_HEADER_PARAMETERS = ['disclosures', 'kb_jwt'];

    /**
     * The size, in bytes, of the random value a decoy digest is computed from.
     */
    private const DECOY_SIZE = 16;

    private int $maximumDecoyDigests;

    /**
     * @param string $hashAlgorithm the IANA name of the hash function of the digests, "sha-256" by default
     * @param int $minimumDecoyDigests the minimum number of decoy digests added to each "_sd" array and array
     * @param int|null $maximumDecoyDigests the maximum number of decoy digests, the minimum when null
     *
     * @throws UnsupportedAlgorithmException if the hash function is not supported
     * @throws InvalidArgumentException if the bounds of the number of decoy digests are not a range
     */
    public function __construct(
        private JWSBuilderInterface $jwsBuilder,
        private string $hashAlgorithm = SDJWT::DEFAULT_HASH_ALGORITHM,
        private int $minimumDecoyDigests = 0,
        ?int $maximumDecoyDigests = null
    ) {
        NamedInformationHash::phpName($hashAlgorithm);
        $maximumDecoyDigests ??= $minimumDecoyDigests;
        if ($minimumDecoyDigests < 0 || $maximumDecoyDigests < $minimumDecoyDigests) {
            throw new InvalidArgumentException(
                'The number of decoy digests must be a range of non-negative integers.'
            );
        }
        $this->maximumDecoyDigests = $maximumDecoyDigests;
    }

    /**
     * @param array<mixed> $claims
     * @param array<string, mixed> $protectedHeader
     */
    #[Override]
    public function issue(array $claims, JWK $signatureKey, array $protectedHeader): SDJWT
    {
        self::checkProtectedHeader($this->jwsBuilder, $protectedHeader);
        [$payload, $disclosures] = $this->payload($claims);
        $jws = $this->jwsBuilder
            ->withPayload($payload)
            ->addSignature($signatureKey, $protectedHeader)
            ->build();

        return SDJWT::create((new CompactSerializer())->serialize($jws, 0), $disclosures);
    }

    /**
     * @param array<mixed> $claims
     */
    #[Override]
    public function issueJson(array $claims, IssuerSignature $signature, IssuerSignature ...$signatures): SDJWT
    {
        $signatures = [$signature, ...$signatures];
        foreach ($signatures as $issuerSignature) {
            self::checkProtectedHeader($this->jwsBuilder, $issuerSignature->getProtectedHeader());
            foreach (self::RESERVED_HEADER_PARAMETERS as $name) {
                if (array_key_exists($name, $issuerSignature->getHeader())) {
                    throw new InvalidArgumentException(sprintf(
                        'The "%s" header parameter is reserved for the SD-JWT.',
                        $name
                    ));
                }
            }
        }
        [$payload, $disclosures] = $this->payload($claims);
        $builder = $this->jwsBuilder->withPayload($payload);
        foreach ($signatures as $issuerSignature) {
            $builder = $builder->addSignature(
                $issuerSignature->getKey(),
                $issuerSignature->getProtectedHeader(),
                $issuerSignature->getHeader()
            );
        }
        $jws = $builder->build();
        $issuerSignedJwt = count($signatures) === 1
            ? (new JSONFlattenedSerializer())->serialize($jws, 0)
            : (new JSONGeneralSerializer())->serialize($jws);

        return SDJWT::create($issuerSignedJwt, $disclosures);
    }

    /**
     * Checks the claims and turns them into the encoded payload of the Issuer-signed JWT and the Disclosures.
     *
     * @param array<mixed> $claims
     *
     * @return array{string, list<Disclosure>}
     */
    private function payload(array $claims): array
    {
        if ($claims !== [] && array_is_list($claims)) {
            throw new InvalidArgumentException('The claims of an SD-JWT must be a JSON object.');
        }
        foreach (self::VALIDITY_CLAIMS as $claimName) {
            if (array_key_exists($claimName, $claims) && $claims[$claimName] instanceof Disclosable) {
                throw new InvalidArgumentException(sprintf(
                    'The claim "%s" cannot be selectively disclosable: the Verifier needs it to evaluate the SD-JWT.',
                    $claimName
                ));
            }
        }
        $disclosures = [];
        $payload = $this->concealObject($claims, $disclosures);
        $salts = array_map(static fn (Disclosure $disclosure): string => $disclosure->getSalt(), $disclosures);
        if (count(array_unique($salts)) !== count($salts)) {
            throw new InvalidArgumentException('The salt of every Disclosure must be unique.');
        }
        $payload['_sd_alg'] = $this->hashAlgorithm;

        return [JsonConverter::encode($payload), $disclosures];
    }

    /**
     * @param list<Disclosure> $disclosures the Disclosures created so far, completed with those of the value
     */
    private function conceal(mixed $value, array &$disclosures): mixed
    {
        if ($value instanceof Disclosable) {
            throw new InvalidArgumentException('A Disclosable cannot be the value of another Disclosable.');
        }
        if (! is_array($value)) {
            return $value;
        }

        return array_is_list($value) ? $this->concealArray($value, $disclosures) : $this->concealObject(
            $value,
            $disclosures
        );
    }

    /**
     * @param array<mixed> $object
     * @param list<Disclosure> $disclosures
     *
     * @return array<mixed>
     */
    private function concealObject(array $object, array &$disclosures): array
    {
        $digests = [];
        $members = [];
        foreach ($object as $name => $value) {
            $name = (string) $name;
            if (in_array($name, self::RESERVED_CLAIM_NAMES, true)) {
                throw new InvalidArgumentException(sprintf('The claim name "%s" is reserved.', $name));
            }
            if (! $value instanceof Disclosable) {
                $members[$name] = $this->conceal($value, $disclosures);
                continue;
            }
            $disclosure = Disclosure::forObjectProperty(
                $name,
                $this->conceal($value->getValue(), $disclosures),
                $value->getSalt()
            );
            $disclosures[] = $disclosure;
            $digests[] = $disclosure->digest($this->hashAlgorithm);
        }
        if ($digests === []) {
            return $members;
        }
        for ($decoys = random_int($this->minimumDecoyDigests, $this->maximumDecoyDigests); $decoys > 0; --$decoys) {
            $digests[] = $this->decoyDigest();
        }
        sort($digests, SORT_STRING);

        return [
            '_sd' => $digests,
        ] + $members;
    }

    /**
     * @param list<mixed> $array
     * @param list<Disclosure> $disclosures
     *
     * @return list<mixed>
     */
    private function concealArray(array $array, array &$disclosures): array
    {
        $elements = [];
        $hasDisclosures = false;
        foreach ($array as $value) {
            if (! $value instanceof Disclosable) {
                $elements[] = $this->conceal($value, $disclosures);
                continue;
            }
            $disclosure = Disclosure::forArrayElement(
                $this->conceal($value->getValue(), $disclosures),
                $value->getSalt()
            );
            $disclosures[] = $disclosure;
            $elements[] = [
                '...' => $disclosure->digest($this->hashAlgorithm),
            ];
            $hasDisclosures = true;
        }
        if (! $hasDisclosures) {
            return $elements;
        }
        for ($decoys = random_int($this->minimumDecoyDigests, $this->maximumDecoyDigests); $decoys > 0; --$decoys) {
            array_splice($elements, random_int(0, count($elements)), 0, [[
                '...' => $this->decoyDigest(),
            ]]);
        }

        return $elements;
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private static function checkProtectedHeader(JWSBuilderInterface $jwsBuilder, array $protectedHeader): void
    {
        if (! self::namesASignatureAlgorithm($jwsBuilder, $protectedHeader)) {
            throw new InvalidArgumentException(
                'The Issuer-signed JWT must be signed: the "alg" header parameter must name a signature algorithm.'
            );
        }
    }

    /**
     * Tells whether the "alg" header parameter names a digital signature algorithm: the Issuer-signed JWT is signed
     * with the private key of the Issuer (section 4.1), so neither "none" nor a MAC algorithm can be used. An algorithm
     * the builder does not know is left to the builder, which reports it.
     *
     * @param array<string, mixed> $protectedHeader
     */
    private static function namesASignatureAlgorithm(JWSBuilderInterface $jwsBuilder, array $protectedHeader): bool
    {
        $algorithm = $protectedHeader['alg'] ?? null;
        if (! is_string($algorithm) || $algorithm === 'none') {
            return false;
        }
        $algorithmManager = $jwsBuilder->getSignatureAlgorithmManager();

        return ! $algorithmManager->has($algorithm) || $algorithmManager->get($algorithm) instanceof SignatureAlgorithm;
    }

    private function decoyDigest(): string
    {
        return Base64UrlSafe::encodeUnpadded(
            NamedInformationHash::hash($this->hashAlgorithm, random_bytes(self::DECOY_SIZE))
        );
    }
}
