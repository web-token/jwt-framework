<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Exception\InvalidHeaderParameterException;
use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\Exception\InvalidPayloadException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\MissingPayloadRuntimeException;
use Jose\Component\Core\Exception\RuntimeException;
use Jose\Component\Core\Exception\UnsupportedAlgorithmException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\InheritanceChecker;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use RangeException;
use function array_key_exists;
use function count;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;
use function trigger_deprecation;

/**
 * Builds a JWS.
 *
 * The builder is immutable: every method that sets the payload or adds a signature returns a new object and
 * never modifies the receiver, so that a builder registered as a shared service cannot be poisoned by a
 * previous build. The consistency of the accumulated state is checked by build(), which makes the order of
 * the calls irrelevant.
 *
 * @final The class will be final in 5.0.0: implement JWSBuilderInterface and decorate the service instead of
 * extending it.
 */
class JWSBuilder implements JWSBuilderInterface
{
    protected ?string $payload = null;

    protected bool $isPayloadDetached = false;

    /**
     * @var list<SignatureSpec>
     */
    protected array $signatures = [];

    /**
     * The payload encoding requested by the first signature.
     *
     * The value is only informative: build() reads the encoding from the signatures themselves and rejects
     * the ones that disagree, whatever the order in which they were added.
     */
    protected ?bool $isPayloadEncoded = null;

    /**
     * Indicates the payload was Base64Url encoded by the caller.
     *
     * This is not the "b64" header parameter, which removes the encoding altogether: here the payload is encoded as
     * usual, the builder simply did not compute that encoding itself.
     */
    protected bool $isPayloadAlreadyEncoded = false;

    public function __construct(
        private readonly AlgorithmManager $signatureAlgorithmManager
    ) {
        InheritanceChecker::warnIfExtended(static::class, self::class, JWSBuilderInterface::class);
    }

    /**
     * Returns the algorithm manager associated to the builder.
     */
    public function getSignatureAlgorithmManager(): AlgorithmManager
    {
        return $this->signatureAlgorithmManager;
    }

    /**
     * Reset the current data.
     *
     * @deprecated since 4.3.0 and will be removed in 5.0.0. The builder is immutable, hence there is no state
     *             to reset: remove the call, or build a new object with "new JWSBuilder($algorithmManager)".
     */
    public function create(): self
    {
        trigger_deprecation(
            'web-token/jwt-framework',
            '4.3.0',
            'The method "%s::create()" is deprecated and will be removed in 5.0.0. The builder is immutable, hence there is no state to reset: remove the call, or build a new object with "new %s($algorithmManager)".',
            self::class,
            self::class
        );

        $clone = clone $this;
        $clone->payload = null;
        $clone->isPayloadDetached = false;
        $clone->signatures = [];
        $clone->isPayloadEncoded = null;
        $clone->isPayloadAlreadyEncoded = false;

        return $clone;
    }

    /**
     * Set the payload. This method will return a new JWSBuilder object.
     */
    public function withPayload(string $payload, bool $isPayloadDetached = false): self
    {
        $clone = clone $this;
        $clone->payload = $payload;
        $clone->isPayloadDetached = $isPayloadDetached;
        $clone->isPayloadAlreadyEncoded = false;

        return $clone;
    }

    /**
     * Set a payload that is already Base64Url encoded. This method will return a new JWSBuilder object.
     *
     * Use it when the payload is only available in its encoded form, so that it is not encoded a second time. The
     * value is decoded and must be a canonical Base64Url string without padding, the only form this library produces
     * and accepts everywhere else.
     *
     * @throws InvalidPayloadException if the payload is not a canonical Base64Url string without padding
     */
    public function withEncodedPayload(string $payload, bool $isPayloadDetached = false): self
    {
        try {
            $decodedPayload = Base64UrlSafe::decodeNoPadding($payload);
        } catch (InvalidArgumentException|RangeException $throwable) {
            throw new InvalidPayloadException(
                'The payload must be a Base64Url encoded string without padding.',
                0,
                $throwable
            );
        }
        $clone = clone $this;
        $clone->payload = $decodedPayload;
        $clone->isPayloadDetached = $isPayloadDetached;
        $clone->isPayloadAlreadyEncoded = true;

        return $clone;
    }

    /**
     * Adds the information needed to compute the signature. This method will return a new JWSBuilder object.
     *
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $header
     */
    public function addSignature(JWK $signatureKey, array $protectedHeader, array $header = []): self
    {
        $this->checkB64AndCriticalHeader($protectedHeader);
        $this->checkDuplicatedHeaderParameters($protectedHeader, $header);
        KeyChecker::checkKeyUsage($signatureKey, 'signature');
        $algorithm = $this->findSignatureAlgorithm($signatureKey, $protectedHeader, $header);
        KeyChecker::checkKeyAlgorithm($signatureKey, $algorithm->name());
        $signature = new SignatureSpec($signatureKey, $algorithm, $protectedHeader, $header);

        $clone = clone $this;
        $clone->signatures[] = $signature;
        $clone->isPayloadEncoded ??= $signature->isPayloadEncoded();

        return $clone;
    }

    /**
     * Computes all signatures and return the expected JWS object.
     */
    public function build(): JWS
    {
        if ($this->payload === null) {
            throw new MissingPayloadRuntimeException('The payload is not set.');
        }
        if (count($this->signatures) === 0) {
            throw new RuntimeException('At least one signature must be set.');
        }
        $isPayloadEncoded = $this->getPayloadEncoding();
        if ($this->isPayloadAlreadyEncoded && $isPayloadEncoded === false) {
            throw new InvalidPayloadException(
                'An encoded payload cannot be used when the protected header parameter "b64" is set to false.'
            );
        }

        $encodedPayload = $isPayloadEncoded === false ? $this->payload : Base64UrlSafe::encodeUnpadded(
            $this->payload
        );

        if ($isPayloadEncoded === false && $this->isPayloadDetached === false) {
            mb_detect_encoding($this->payload, 'UTF-8', true) !== false || throw new InvalidPayloadException(
                'The payload must be encoded in UTF-8'
            );
        }

        $jws = new JWS($this->payload, $encodedPayload, $this->isPayloadDetached);
        foreach ($this->signatures as $signature) {
            $algorithm = $signature->algorithm;
            $protectedHeader = $signature->protectedHeader;
            $encodedProtectedHeader = count($protectedHeader) === 0 ? null : Base64UrlSafe::encodeUnpadded(
                JsonConverter::encode($protectedHeader)
            );
            $input = sprintf('%s.%s', $encodedProtectedHeader, $encodedPayload);
            if ($algorithm instanceof SignatureAlgorithm) {
                $s = $algorithm->sign($signature->key, $input);
            } else {
                $s = $algorithm->hash($signature->key, $input);
            }
            $jws = $jws->addSignature($s, $protectedHeader, $encodedProtectedHeader, $signature->header);
        }

        return $jws;
    }

    /**
     * Returns the signatures in the array shape the builder used before 4.3.0.
     *
     * @internal
     * @return array<array{
     *     signature_algorithm: MacAlgorithm|SignatureAlgorithm,
     *     signature_key: JWK,
     *     protected_header: array<string, mixed>,
     *     header: array<string, mixed>
     * }>
     */
    protected function getSignaturesAsArray(): array
    {
        $signatures = [];
        foreach ($this->signatures as $signature) {
            $signatures[] = [
                'signature_algorithm' => $signature->algorithm,
                'signature_key' => $signature->key,
                'protected_header' => $signature->protectedHeader,
                'header' => $signature->header,
            ];
        }

        return $signatures;
    }

    /**
     * Returns the payload encoding shared by all the signatures.
     *
     * @throws InvalidPayloadException if the signatures do not agree on the encoding of the payload
     */
    private function getPayloadEncoding(): bool
    {
        $isPayloadEncoded = null;
        foreach ($this->signatures as $signature) {
            $currentEncoding = $signature->isPayloadEncoded();
            if ($isPayloadEncoded === null) {
                $isPayloadEncoded = $currentEncoding;

                continue;
            }
            if ($isPayloadEncoded !== $currentEncoding) {
                throw new InvalidPayloadException('Foreign payload encoding detected.');
            }
        }

        return $isPayloadEncoded ?? true;
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private function checkB64AndCriticalHeader(array $protectedHeader): void
    {
        if (! array_key_exists('b64', $protectedHeader)) {
            return;
        }
        if (! array_key_exists('crit', $protectedHeader)) {
            throw new LogicException(
                'The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.'
            );
        }
        if (! is_array($protectedHeader['crit'])) {
            throw new LogicException('The protected header parameter "crit" must be an array.');
        }
        if (! in_array('b64', $protectedHeader['crit'], true)) {
            throw new LogicException(
                'The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.'
            );
        }
    }

    /**
     * @param array<string, mixed> $protectedHeader
     * @param array<string, mixed> $header
     */
    private function findSignatureAlgorithm(
        JWK $key,
        array $protectedHeader,
        array $header
    ): MacAlgorithm|SignatureAlgorithm {
        $completeHeader = [...$header, ...$protectedHeader];
        $alg = $completeHeader['alg'] ?? null;
        if (! is_string($alg)) {
            throw new InvalidHeaderParameterException('No "alg" parameter set in the header.');
        }
        $keyAlg = $key->has('alg') ? $key->get('alg') : null;
        if (is_string($keyAlg) && $keyAlg !== $alg) {
            throw new InvalidKeyException(sprintf('The algorithm "%s" is not allowed with this key.', $alg));
        }

        $algorithm = $this->signatureAlgorithmManager->get($alg);
        if (! $algorithm instanceof SignatureAlgorithm && ! $algorithm instanceof MacAlgorithm) {
            throw new UnsupportedAlgorithmException(sprintf('The algorithm "%s" is not supported.', $alg));
        }

        return $algorithm;
    }

    /**
     * @param array<string, mixed> $header1
     * @param array<string, mixed> $header2
     */
    private function checkDuplicatedHeaderParameters(array $header1, array $header2): void
    {
        $inter = array_intersect_key($header1, $header2);
        if (count($inter) !== 0) {
            throw new InvalidHeaderParameterException(sprintf(
                'The header contains duplicated entries: %s.',
                implode(', ', array_keys($inter))
            ));
        }
    }
}
