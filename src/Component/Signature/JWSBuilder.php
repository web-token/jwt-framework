<?php

declare(strict_types=1);

namespace Jose\Component\Signature;

use function array_key_exists;
use function count;
use function in_array;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use LogicException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

class JWSBuilder
{
    protected ?string $payload = null;

    protected bool $isPayloadDetached = false;

    /**
     * @var array<array{
     *     header: array<string, mixed>,
     *     protected_header: array<string, mixed>,
     *     signature_key: JWK,
     *     signature_algorithm: Algorithm
     * }>
     */
    protected array $signatures = [];

    protected ?bool $isPayloadEncoded = null;

    public function __construct(
        private readonly AlgorithmManager $signatureAlgorithmManager
    ) {
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
     */
    public function create(): self
    {
        $this->payload = null;
        $this->isPayloadDetached = false;
        $this->signatures = [];
        $this->isPayloadEncoded = null;

        return $this;
    }

    /**
     * Set the payload. This method will return a new JWSBuilder object.
     */
    public function withPayload(string $payload, bool $isPayloadDetached = false): self
    {
        if (mb_detect_encoding($payload, 'UTF-8', true) === false) {
            throw new InvalidArgumentException('The payload must be encoded in UTF-8');
        }
        $clone = clone $this;
        $clone->payload = $payload;
        $clone->isPayloadDetached = $isPayloadDetached;

        return $clone;
    }

    /**
     * Adds the information needed to compute the signature. This method will return a new JWSBuilder object.
     *
     * @param array{alg?: string, string?: mixed} $protectedHeader
     * @param array{alg?: string, string?: mixed} $header
     */
    public function addSignature(JWK $signatureKey, array $protectedHeader, array $header = []): self
    {
        $this->checkB64AndCriticalHeader($protectedHeader);
        $isPayloadEncoded = $this->checkIfPayloadIsEncoded($protectedHeader);
        if ($this->isPayloadEncoded === null) {
            $this->isPayloadEncoded = $isPayloadEncoded;
        } elseif ($this->isPayloadEncoded !== $isPayloadEncoded) {
            throw new InvalidArgumentException('Foreign payload encoding detected.');
        }
        $this->checkDuplicatedHeaderParameters($protectedHeader, $header);
        KeyChecker::checkKeyUsage($signatureKey, 'signature');
        $algorithm = $this->findSignatureAlgorithm($signatureKey, $protectedHeader, $header);
        KeyChecker::checkKeyAlgorithm($signatureKey, $algorithm->name());
        $clone = clone $this;
        $clone->signatures[] = [
            'signature_algorithm' => $algorithm,
            'signature_key' => $signatureKey,
            'protected_header' => $protectedHeader,
            'header' => $header,
        ];

        return $clone;
    }

    /**
     * Computes all signatures and return the expected JWS object.
     */
    public function build(): JWS
    {
        if ($this->payload === null) {
            throw new RuntimeException('The payload is not set.');
        }
        if (count($this->signatures) === 0) {
            throw new RuntimeException('At least one signature must be set.');
        }

        $encodedPayload = $this->isPayloadEncoded === false ? $this->payload : Base64UrlSafe::encodeUnpadded(
            $this->payload
        );
        $jws = new JWS($this->payload, $encodedPayload, $this->isPayloadDetached);
        foreach ($this->signatures as $signature) {
            /** @var MacAlgorithm|SignatureAlgorithm $algorithm */
            $algorithm = $signature['signature_algorithm'];
            /** @var JWK $signatureKey */
            $signatureKey = $signature['signature_key'];
            /** @var array<string, mixed> $protectedHeader */
            $protectedHeader = $signature['protected_header'];
            /** @var array<string, mixed> $header */
            $header = $signature['header'];
            $encodedProtectedHeader = count($protectedHeader) === 0 ? null : Base64UrlSafe::encodeUnpadded(
                JsonConverter::encode($protectedHeader)
            );
            $input = sprintf('%s.%s', $encodedProtectedHeader, $encodedPayload);
            if ($algorithm instanceof SignatureAlgorithm) {
                $s = $algorithm->sign($signatureKey, $input);
            } else {
                $s = $algorithm->hash($signatureKey, $input);
            }
            $jws = $jws->addSignature($s, $protectedHeader, $encodedProtectedHeader, $header);
        }

        return $jws;
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private function checkIfPayloadIsEncoded(array $protectedHeader): bool
    {
        return ! array_key_exists('b64', $protectedHeader) || $protectedHeader['b64'] === true;
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
     * @param array{alg?: string, string?: mixed} $protectedHeader
     * @param array{alg?: string, string?: mixed} $header
     * @return MacAlgorithm|SignatureAlgorithm
     */
    private function findSignatureAlgorithm(JWK $key, array $protectedHeader, array $header): Algorithm
    {
        $completeHeader = [...$header, ...$protectedHeader];
        if (! array_key_exists('alg', $completeHeader)) {
            throw new InvalidArgumentException('No "alg" parameter set in the header.');
        }
        if ($key->has('alg') && $key->get('alg') !== $completeHeader['alg']) {
            throw new InvalidArgumentException(sprintf(
                'The algorithm "%s" is not allowed with this key.',
                $completeHeader['alg']
            ));
        }

        $algorithm = $this->signatureAlgorithmManager->get($completeHeader['alg']);
        if (! $algorithm instanceof SignatureAlgorithm && ! $algorithm instanceof MacAlgorithm) {
            throw new InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $completeHeader['alg']));
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
            throw new InvalidArgumentException(sprintf(
                'The header contains duplicated entries: %s.',
                implode(', ', array_keys($inter))
            ));
        }
    }
}
