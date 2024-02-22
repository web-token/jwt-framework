<?php

declare(strict_types=1);

namespace Jose\Tests\Component\Signature;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use PHPUnit\Framework\TestCase;

abstract class SignatureTestCase extends TestCase
{
    private ?AlgorithmManagerFactory $algorithmManagerFactory = null;

    private ?JWSBuilderFactory $jwsBuilderFactory = null;

    private ?JWSVerifierFactory $jwsVerifierFactory = null;

    private ?JWSSerializerManagerFactory $jwsSerializerManagerFactory = null;

    private ?JWSSerializerManager $jwsSerializerManager = null;

    private ?JWSLoaderFactory $jwsLoaderFactory = null;

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if ($this->algorithmManagerFactory === null) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory([
                new HS256(),
                new HS384(),
                new HS512(),
                new ES256(),
                new ES384(),
                new ES512(),
                new RS256(),
                new RS384(),
                new RS512(),
                new PS256(),
                new PS384(),
                new PS512(),
                new None(),
                new EdDSA(),
            ]);
        }

        return $this->algorithmManagerFactory;
    }

    protected function getJWSBuilderFactory(): JWSBuilderFactory
    {
        if ($this->jwsBuilderFactory === null) {
            $this->jwsBuilderFactory = new JWSBuilderFactory($this->getAlgorithmManagerFactory());
        }

        return $this->jwsBuilderFactory;
    }

    protected function getJWSVerifierFactory(): JWSVerifierFactory
    {
        if ($this->jwsVerifierFactory === null) {
            $this->jwsVerifierFactory = new JWSVerifierFactory($this->getAlgorithmManagerFactory());
        }

        return $this->jwsVerifierFactory;
    }

    protected function getJWSSerializerManagerFactory(): JWSSerializerManagerFactory
    {
        if ($this->jwsSerializerManagerFactory === null) {
            $this->jwsSerializerManagerFactory = new JWSSerializerManagerFactory();
            $this->jwsSerializerManagerFactory->add(new CompactSerializer());
            $this->jwsSerializerManagerFactory->add(new JSONFlattenedSerializer());
            $this->jwsSerializerManagerFactory->add(new JSONGeneralSerializer());
        }

        return $this->jwsSerializerManagerFactory;
    }

    protected function getJWSSerializerManager(): JWSSerializerManager
    {
        if ($this->jwsSerializerManager === null) {
            $this->jwsSerializerManager = new JWSSerializerManager([
                new CompactSerializer(),
                new JSONFlattenedSerializer(),
                new JSONGeneralSerializer(),
            ]);
        }

        return $this->jwsSerializerManager;
    }

    protected function getJWSLoaderFactory(): JWSLoaderFactory
    {
        if ($this->jwsLoaderFactory === null) {
            $this->jwsLoaderFactory = new JWSLoaderFactory(
                $this->getJWSSerializerManagerFactory(),
                $this->getJWSVerifierFactory(),
                null
            );
        }

        return $this->jwsLoaderFactory;
    }
}
