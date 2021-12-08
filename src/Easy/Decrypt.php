<?php

declare(strict_types=1);

namespace Jose\Easy;

use function count;
use InvalidArgumentException;
use function is_string;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A192GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHESA256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSA15;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethod;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Serializer\CompactSerializer;

class Decrypt extends AbstractLoader
{
    /**
     * @var string[]
     */
    protected array $allowedContentEncryptionAlgorithms = [];

    /**
     * @var CompressionMethod[]
     */
    private array $compressionMethods;

    private function __construct(string $token)
    {
        parent::__construct($token);
        $this->compressionMethods = [new Deflate()];
    }

    public static function token(string $token): self
    {
        return new self($token);
    }

    public function enc(Algorithm|string $enc): self
    {
        $clone = clone $this;

        switch (true) {
            case is_string($enc):
                $clone->allowedContentEncryptionAlgorithms[] = $enc;

                return $clone;

            case $enc instanceof Algorithm:
                $clone->algorithms[$enc->name()] = $enc;
                $clone->allowedContentEncryptionAlgorithms[] = $enc->name();

                return $clone;

            default:
                throw new InvalidArgumentException(
                    'Invalid parameter "enc". Shall be a string or an algorithm instance.'
                );
        }
    }

    /**
     * @param Algorithm[]|string[] $encs
     */
    public function encs($encs): self
    {
        $clone = clone $this;
        foreach ($encs as $enc) {
            $clone = $clone->enc($enc);
        }

        return $clone;
    }

    public function run(): JWT
    {
        if (count($this->allowedAlgorithms) !== 0) {
            $this->headerCheckers[] = new AlgorithmChecker($this->allowedAlgorithms, true);
        }
        if (count($this->allowedContentEncryptionAlgorithms) !== 0) {
            $this->headerCheckers[] = new ContentEncryptionAlgorithmChecker(
                $this->allowedContentEncryptionAlgorithms,
                true
            );
        }
        $jwe = (new CompactSerializer())->unserialize($this->token);
        $headerChecker = new HeaderCheckerManager($this->headerCheckers, [new JWETokenSupport()]);
        $headerChecker->check($jwe, 0);

        $verifier = new JWEDecrypter(
            new AlgorithmManager($this->algorithms),
            new AlgorithmManager($this->algorithms),
            new CompressionMethodManager($this->compressionMethods)
        );
        $verifier->decryptUsingKeySet($jwe, $this->jwkset, 0);

        $jwt = new JWT();
        $jwt->header->replace($jwe->getSharedProtectedHeader());
        $jwt->claims->replace(JsonConverter::decode($jwe->getPayload()));

        $claimChecker = new ClaimCheckerManager($this->claimCheckers);
        $claimChecker->check($jwt->claims->all(), $this->mandatoryClaims);

        return $jwt;
    }

    protected function getAlgorithmMap(): array
    {
        return [
            A128GCMKW::class,
            A192GCMKW::class,
            A256GCMKW::class,
            A128KW::class,
            A192KW::class,
            A256KW::class,
            Dir::class,
            ECDHES::class,
            ECDHESA128KW::class,
            ECDHESA192KW::class,
            ECDHESA256KW::class,
            PBES2HS256A128KW::class,
            PBES2HS384A192KW::class,
            PBES2HS512A256KW::class,
            RSA15::class,
            RSAOAEP::class,
            RSAOAEP256::class,
            A128GCM::class,
            A192GCM::class,
            A256GCM::class,
            A128CBCHS256::class,
            A192CBCHS384::class,
            A256CBCHS512::class,
        ];
    }
}
