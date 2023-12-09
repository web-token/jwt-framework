<?php

declare(strict_types=1);

namespace Jose\Component\Signature\Serializer;

use InvalidArgumentException;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWS;
use ParagonIE\ConstantTime\Base64UrlSafe;
use function count;
use function is_array;

final class JSONFlattenedSerializer extends Serializer
{
    public const NAME = 'jws_json_flattened';

    public function displayName(): string
    {
        return 'JWS JSON Flattened';
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function serialize(JWS $jws, ?int $signatureIndex = null): string
    {
        if ($signatureIndex === null) {
            $signatureIndex = 0;
        }
        $signature = $jws->getSignature($signatureIndex);

        $data = [];
        $encodedPayload = $jws->getEncodedPayload();
        if ($encodedPayload !== null && $encodedPayload !== '') {
            $data['payload'] = $encodedPayload;
        }
        $encodedProtectedHeader = $signature->getEncodedProtectedHeader();
        if ($encodedProtectedHeader !== null && $encodedProtectedHeader !== '') {
            $data['protected'] = $encodedProtectedHeader;
        }
        $header = $signature->getHeader();
        if (count($header) !== 0) {
            $data['header'] = $header;
        }
        $data['signature'] = Base64UrlSafe::encodeUnpadded($signature->getSignature());

        return JsonConverter::encode($data);
    }

    public function unserialize(string $input): JWS
    {
        $data = JsonConverter::decode($input);
        if (! is_array($data)) {
            throw new InvalidArgumentException('Unsupported input.');
        }
        if (! isset($data['signature'])) {
            throw new InvalidArgumentException('Unsupported input.');
        }
        $signature = Base64UrlSafe::decode($data['signature']);

        if (isset($data['protected'])) {
            $encodedProtectedHeader = $data['protected'];
            $protectedHeader = JsonConverter::decode(Base64UrlSafe::decode($data['protected']));
            if (! is_array($protectedHeader)) {
                throw new InvalidArgumentException('Bad protected header.');
            }
        } else {
            $encodedProtectedHeader = null;
            $protectedHeader = [];
        }
        if (isset($data['header'])) {
            if (! is_array($data['header'])) {
                throw new InvalidArgumentException('Bad header.');
            }
            $header = $data['header'];
        } else {
            $header = [];
        }

        if (isset($data['payload'])) {
            $encodedPayload = $data['payload'];
            $payload = $this->isPayloadEncoded($protectedHeader) ? Base64UrlSafe::decode(
                $encodedPayload
            ) : $encodedPayload;
        } else {
            $payload = null;
            $encodedPayload = null;
        }

        $jws = new JWS($payload, $encodedPayload, $encodedPayload === null);

        return $jws->addSignature($signature, $protectedHeader, $encodedProtectedHeader, $header);
    }
}
