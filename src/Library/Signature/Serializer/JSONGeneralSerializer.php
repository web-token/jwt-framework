<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Serializer;

use Jose\Component\Core\Exception\InvalidPayloadException;
use Jose\Component\Core\Exception\InvalidSerializationException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\Exception\UnrecognizedSerializationException;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\BoundedJsonDecoder;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\Signature;
use Override;
use SensitiveParameter;
use function array_key_exists;
use function count;
use function is_array;
use function is_string;

final readonly class JSONGeneralSerializer extends Serializer
{
    public const NAME = 'jws_json_general';

    #[Override]
    public function displayName(): string
    {
        return 'JWS JSON General';
    }

    #[Override]
    public function name(): string
    {
        return self::NAME;
    }

    #[Override]
    public function serialize(JWS $jws, ?int $signatureIndex = null): string
    {
        if ($jws->countSignatures() === 0) {
            throw new LogicException('No signature.');
        }

        $data = [];
        $this->checkPayloadEncoding($jws);

        $encodedPayload = $jws->getEncodedPayload();
        if ($encodedPayload !== null) {
            $data['payload'] = $encodedPayload;
        }

        $data['signatures'] = [];
        foreach ($jws->getSignatures() as $signature) {
            $tmp = [
                'signature' => Base64UrlSafe::encodeUnpadded($signature->getSignature()),
            ];
            $values = [
                'protected' => $signature->getEncodedProtectedHeader(),
                'header' => $signature->getHeader(),
            ];

            foreach ($values as $key => $value) {
                if ((is_string($value) && $value !== '') || (is_array($value) && count($value) !== 0)) {
                    $tmp[$key] = $value;
                }
            }
            $data['signatures'][] = $tmp;
        }

        return JsonConverter::encode($data);
    }

    #[Override]
    public function unserialize(#[SensitiveParameter] string $input): JWS
    {
        $json = new BoundedJsonDecoder();
        $data = $json->decodeSerialization($input);
        if (! is_array($data) || ! isset($data['signatures'])) {
            throw new UnrecognizedSerializationException('Unsupported input.');
        }

        $isPayloadEncoded = null;
        $rawPayload = $data['payload'] ?? null;
        $signatures = [];
        foreach ($data['signatures'] as $signature) {
            if (! isset($signature['signature'])) {
                throw new InvalidSerializationException('Unsupported input.');
            }
            [$encodedProtectedHeader, $protectedHeader, $header] = $this->processHeaders($signature, $json);
            $signatures[] = [
                'signature' => Base64UrlSafe::decodeNoPadding($signature['signature']),
                'protected' => $protectedHeader,
                'encoded_protected' => $encodedProtectedHeader,
                'header' => $header,
            ];
            $isPayloadEncoded = $this->processIsPayloadEncoded($isPayloadEncoded, $protectedHeader);
        }

        $payload = $this->processPayload($rawPayload, $isPayloadEncoded);
        $jwsSignatures = [];
        foreach ($signatures as $signature) {
            $jwsSignatures[] = new Signature(
                $signature['signature'],
                $signature['protected'],
                $signature['encoded_protected'],
                $signature['header']
            );
        }

        return new JWS($payload, $rawPayload, $rawPayload === null, $jwsSignatures);
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    private function processIsPayloadEncoded(?bool $isPayloadEncoded, array $protectedHeader): bool
    {
        if ($isPayloadEncoded === null) {
            return $this->isPayloadEncoded($protectedHeader);
        }
        if ($this->isPayloadEncoded($protectedHeader) !== $isPayloadEncoded) {
            throw new InvalidPayloadException('Foreign payload encoding detected.');
        }

        return $isPayloadEncoded;
    }

    /**
     * @param array{protected?: string, header?: array<string, mixed>} $signature
     * @return array<mixed>
     */
    private function processHeaders(array $signature, BoundedJsonDecoder $json): array
    {
        $encodedProtectedHeader = $signature['protected'] ?? null;
        $protectedHeader = $encodedProtectedHeader === null ? [] : $json->decode(
            Base64UrlSafe::decodeNoPadding($encodedProtectedHeader)
        );
        $header = array_key_exists('header', $signature) ? $signature['header'] : [];

        return [$encodedProtectedHeader, $protectedHeader, $header];
    }

    private function processPayload(#[SensitiveParameter] ?string $rawPayload, ?bool $isPayloadEncoded): ?string
    {
        if ($rawPayload === null) {
            return null;
        }

        return $isPayloadEncoded === false ? $rawPayload : Base64UrlSafe::decodeNoPadding($rawPayload);
    }

    private function checkPayloadEncoding(JWS $jws): void
    {
        if ($jws->isPayloadDetached()) {
            return;
        }
        $is_encoded = null;
        foreach ($jws->getSignatures() as $signature) {
            $is_encoded ??= $this->isPayloadEncoded($signature->getProtectedHeader());
            if ($is_encoded !== $this->isPayloadEncoded($signature->getProtectedHeader())) {
                throw new LogicException('Foreign payload encoding detected.');
            }
        }
    }
}
