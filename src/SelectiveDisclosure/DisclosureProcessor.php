<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Core\Exception\InvalidTokenException;
use function array_is_list;
use function array_key_exists;
use function array_values;
use function count;
use function hash_hmac;
use function is_array;
use function is_string;
use function random_bytes;
use function sprintf;

/**
 * Processes the payload of an Issuer-signed JWT with the Disclosures of the SD-JWT, as RFC 9901 section 7.1 step 3
 * describes, and enforces the rules of steps 4 and 5.
 *
 * The digests are looked for in the "_sd" arrays of the objects and in the {"...": digest} elements of the arrays, of
 * the payload and, recursively, of the disclosed values. A digest that matches no Disclosure is a decoy, or the digest
 * of a claim that is not disclosed: it is ignored, and so is the array element that carries it. The SD-JWT is
 * rejected when:
 *
 * - a digest appears twice, whether it matches a Disclosure or not;
 * - a Disclosure is presented twice, or is not referenced by any digest;
 * - the Disclosure of an array element is referenced from an object, or the other way round;
 * - a disclosed claim already exists in its object;
 * - "_sd" is not an array of strings, "..." does not carry a string, or a "..." member is found outside of the
 *   {"...": digest} elements of an array (section 4.1);
 * - the processed payload has more than 64 levels of objects and arrays, itself included. RFC 9901 sets no limit,
 *   and the depth limit of the JSON decoder does not apply: each Disclosure is decoded apart.
 *
 * Every failure is reported by an InvalidTokenException. The processor also records the path of each disclosed value
 * in the processed payload, which is how the Holder selects the Disclosures of a claim.
 *
 * @internal
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1
 */
final class DisclosureProcessor
{
    private const MAXIMUM_DEPTH = 64;

    /**
     * The secret of this processing: the digests are recorded under a hash keyed with it, see index().
     */
    private readonly string $key;

    /**
     * @var list<Disclosure>
     */
    private readonly array $disclosures;

    /**
     * The position of each Disclosure, indexed by the keyed hash of its digest.
     *
     * @var array<string, int>
     */
    private array $positions = [];

    /**
     * @var array<string, true>
     */
    private array $digests = [];

    /**
     * @var array<int, list<string|int>>
     */
    private array $paths = [];

    /**
     * @param list<Disclosure> $disclosures
     */
    private function __construct(array $disclosures, string $hashAlgorithm)
    {
        $this->key = random_bytes(32);
        $this->disclosures = array_values($disclosures);
        foreach ($this->disclosures as $position => $disclosure) {
            $index = $this->index($disclosure->digest($hashAlgorithm));
            if (array_key_exists($index, $this->positions)) {
                throw new InvalidTokenException('A Disclosure is presented more than once.');
            }
            $this->positions[$index] = $position;
        }
    }

    /**
     * Processes the payload and returns the Processed SD-JWT Payload, without "_sd_alg", and the path of the value
     * disclosed by each Disclosure, indexed by the position of the Disclosure in the given list.
     *
     * @param array<mixed> $payload the payload of the Issuer-signed JWT, a JSON object
     * @param list<Disclosure> $disclosures
     *
     * @return array{claims: array<string, mixed>, paths: array<int, list<string|int>>}
     */
    public static function process(array $payload, array $disclosures, string $hashAlgorithm): array
    {
        $processor = new self($disclosures, $hashAlgorithm);
        $claims = $processor->processObject($payload, []);
        unset($claims['_sd_alg']);
        if (count($processor->paths) !== count($processor->disclosures)) {
            throw new InvalidTokenException('A Disclosure is not referenced by the SD-JWT.');
        }

        return [
            'claims' => $claims,
            'paths' => $processor->paths,
        ];
    }

    /**
     * The hash algorithm declared by the "_sd_alg" claim of the payload, "sha-256" when the claim is absent (section
     * 4.1.1). Whether the algorithm is supported, or accepted, is left to the caller.
     *
     * @param array<mixed> $payload
     */
    public static function declaredHashAlgorithm(array $payload): string
    {
        if (! array_key_exists('_sd_alg', $payload)) {
            return SDJWT::DEFAULT_HASH_ALGORITHM;
        }
        if (! is_string($payload['_sd_alg'])) {
            throw new InvalidTokenException('The "_sd_alg" claim must be a string.');
        }

        return $payload['_sd_alg'];
    }

    /**
     * @param list<string|int> $path
     */
    private function processValue(mixed $value, array $path): mixed
    {
        if (! is_array($value)) {
            return $value;
        }
        $depth = count($path) + 1;
        if ($depth > self::MAXIMUM_DEPTH) {
            throw new InvalidTokenException(sprintf(
                'The processed payload of the SD-JWT is nested more than %d levels deep.',
                self::MAXIMUM_DEPTH
            ));
        }

        return array_is_list($value) ? $this->processArray($value, $path) : $this->processObject($value, $path);
    }

    /**
     * Processes the members of the object, then inserts the claims disclosed by the digests of its "_sd" array: a
     * disclosed claim is compared to every member of the object and to the claims disclosed before it.
     *
     * @param array<mixed> $object
     * @param list<string|int> $path
     *
     * @return array<string, mixed>
     */
    private function processObject(array $object, array $path): array
    {
        $claims = [];
        foreach ($object as $name => $value) {
            $name = (string) $name;
            if ($name === '_sd') {
                continue;
            }
            if ($name === '...') {
                throw new InvalidTokenException('The claim name "..." is reserved.');
            }
            $claims[$name] = $this->processValue($value, [...$path, $name]);
        }
        if (! array_key_exists('_sd', $object)) {
            return $claims;
        }
        $digests = $object['_sd'];
        if (! is_array($digests) || ! array_is_list($digests)) {
            throw new InvalidTokenException('The "_sd" member must be an array of digests.');
        }
        foreach ($digests as $digest) {
            if (! is_string($digest)) {
                throw new InvalidTokenException('The "_sd" member must be an array of digests.');
            }
            $position = $this->find($digest);
            if ($position === null) {
                continue;
            }
            $disclosure = $this->disclosures[$position];
            $claimName = $disclosure->getClaimName();
            if ($claimName === null) {
                throw new InvalidTokenException('The Disclosure of an array element is referenced by an object.');
            }
            if (array_key_exists($claimName, $claims)) {
                throw new InvalidTokenException(sprintf('The disclosed claim "%s" already exists.', $claimName));
            }
            $this->paths[$position] = [...$path, $claimName];
            $claims[$claimName] = $this->processValue($disclosure->getValue(), [...$path, $claimName]);
        }

        return $claims;
    }

    /**
     * Processes the elements of the array. An element {"...": digest} is replaced by the value of its Disclosure, or
     * removed when there is none; the index recorded in the paths is the one in the processed array.
     *
     * @param list<mixed> $array
     * @param list<string|int> $path
     *
     * @return list<mixed>
     */
    private function processArray(array $array, array $path): array
    {
        $elements = [];
        foreach ($array as $element) {
            if (! is_array($element) || count($element) !== 1 || ! array_key_exists('...', $element)) {
                $elements[] = $this->processValue($element, [...$path, count($elements)]);
                continue;
            }
            $digest = $element['...'];
            if (! is_string($digest)) {
                throw new InvalidTokenException('The "..." member must be a digest.');
            }
            $position = $this->find($digest);
            if ($position === null) {
                continue;
            }
            $disclosure = $this->disclosures[$position];
            if (! $disclosure->isArrayElement()) {
                throw new InvalidTokenException('The Disclosure of an object property is referenced by an array.');
            }
            $this->paths[$position] = [...$path, count($elements)];
            $elements[] = $this->processValue($disclosure->getValue(), [...$path, count($elements)]);
        }

        return $elements;
    }

    /**
     * Returns the position of the Disclosure the digest references, if any, after having checked that the digest is met
     * for the first time.
     */
    private function find(string $digest): ?int
    {
        $index = $this->index($digest);
        if (array_key_exists($index, $this->digests)) {
            throw new InvalidTokenException(sprintf('The digest "%s" appears more than once in the SD-JWT.', $digest));
        }
        $this->digests[$index] = true;

        return $this->positions[$index] ?? null;
    }

    /**
     * The key a digest is recorded under: its HMAC with the secret of this processing, which the token cannot predict.
     */
    private function index(string $digest): string
    {
        return hash_hmac('sha256', $digest, $this->key, true);
    }
}
