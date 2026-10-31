<?php

declare(strict_types=1);

namespace Jose\SelectiveDisclosure;

use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\TypeChecker;
use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\Exception\LogicException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilderInterface;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Override;
use Psr\Clock\ClockInterface;
use function array_key_exists;
use function is_string;

/**
 * Creates the Key Binding JWTs of RFC 9901 section 4.3.
 *
 * The Key Binding JWT carries the "nonce" and "aud" of the Verifier, its creation time "iat", taken from the clock, and
 * "sd_hash", the digest of the presented SD-JWT, which binds it to the Issuer-signed JWT and to the exact set of
 * Disclosures that is presented. No other claim is added, as the section recommends. Its "typ" is "kb+jwt", checked
 * by the TypeChecker when it is given. It is signed with a digital
 * signature algorithm: neither "none" nor a MAC algorithm, that a key shared with another party could compute.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9901.html#section-4.3
 */
final readonly class SDJWTHolder implements SDJWTHolderInterface
{
    public function __construct(
        private JWSBuilderInterface $jwsBuilder,
        private ClockInterface $clock
    ) {
    }

    /**
     * @param array<string, mixed> $protectedHeader
     *
     * @throws LogicException if the SD-JWT already has a Key Binding JWT
     * @throws InvalidArgumentException if the protected header does not name a signature algorithm, or another type
     */
    #[Override]
    public function present(
        SDJWT $sdJwt,
        JWK $holderKey,
        array $protectedHeader,
        string $audience,
        string $nonce
    ): SDJWT {
        if ($sdJwt->hasKeyBinding()) {
            throw new LogicException('The SD-JWT already has a Key Binding JWT.');
        }
        $algorithm = $protectedHeader['alg'] ?? null;
        $algorithmManager = $this->jwsBuilder->getSignatureAlgorithmManager();
        if (! is_string($algorithm) || $algorithm === 'none' || ($algorithmManager->has($algorithm)
            && ! $algorithmManager->get($algorithm) instanceof SignatureAlgorithm)) {
            throw new InvalidArgumentException(
                'The Key Binding JWT must be signed: the "alg" header parameter must name a signature algorithm.'
            );
        }
        if (! array_key_exists('typ', $protectedHeader)) {
            $protectedHeader['typ'] = SDJWT::KEY_BINDING_JWT_TYPE;
        }
        try {
            (new TypeChecker([SDJWT::KEY_BINDING_JWT_TYPE]))->checkHeader($protectedHeader['typ']);
        } catch (InvalidHeaderException $exception) {
            throw new InvalidArgumentException('The Key Binding JWT must be of type "kb+jwt".', 0, $exception);
        }
        $payload = [
            'nonce' => $nonce,
            'aud' => $audience,
            'iat' => $this->clock->now()
                ->getTimestamp(),
            'sd_hash' => $sdJwt->getSdHash(),
        ];
        $jws = $this->jwsBuilder
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($holderKey, $protectedHeader)
            ->build();

        return $sdJwt->withKeyBindingJwt((new CompactSerializer())->serialize($jws, 0));
    }
}
