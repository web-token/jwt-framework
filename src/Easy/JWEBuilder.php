<?php

declare(strict_types=1);

namespace Jose\Easy;

use InvalidArgumentException;
use function is_string;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\Algorithm as JoseAlgorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
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
use Jose\Component\Encryption\JWEBuilder as JoseBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;

class JWEBuilder extends AbstractBuilder
{
    /**
     * @var JoseAlgorithm[]
     */
    protected array $contentEncryptionAlgorithms = [];

    /**
     * @var CompressionMethod[]
     */
    private array $compressionMethods;

    public function __construct()
    {
        parent::__construct();
        $this->compressionMethods = [new Deflate()];
    }

    public function enc(Algorithm|string $enc): self
    {
        $clone = clone $this;

        switch (true) {
            case $enc instanceof Algorithm:
                $clone->contentEncryptionAlgorithms[] = $enc;
                $clone->jwt->header->set('enc', $enc->name());

                break;

            case is_string($enc):
                $clone->jwt->header->set('enc', $enc);

                break;

            default:
                throw new InvalidArgumentException('Invalid algorithm');
        }

        return $clone;
    }

    public function zip(CompressionMethod|string $zip): self
    {
        $clone = clone $this;

        switch (true) {
            case $zip instanceof CompressionMethod:
                $clone->compressionMethods[] = $zip;
                $clone->jwt->header->set('zip', $zip->name());

                break;

            case is_string($zip):
                $clone->jwt->header->set('zip', $zip);

                break;

            default:
                throw new InvalidArgumentException('Invalid compression method');
        }

        return $clone;
    }

    public function encrypt(JWK $jwk): string
    {
        $builder = new JoseBuilder(
            new AlgorithmManager($this->algorithms),
            new AlgorithmManager($this->contentEncryptionAlgorithms),
            new CompressionMethodManager($this->compressionMethods)
        );
        $jwe = $builder
            ->create()
            ->withPayload(JsonConverter::encode($this->jwt->claims->all()))
            ->withSharedProtectedHeader($this->jwt->header->all())
            ->addRecipient($jwk)
            ->build()
        ;

        return (new CompactSerializer())->serialize($jwe);
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
