<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2020 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Tests;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWSBuilderFactory;
use Jose\Component\Signature\JWSLoaderFactory;
use Jose\Component\Signature\JWSVerifierFactory;
use Jose\Component\Signature\Serializer;
use PHPUnit\Framework\TestCase;

abstract class SignatureTest extends TestCase
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var JWSBuilderFactory
     */
    private $jwsBuilderFactory;

    /**
     * @var JWSVerifierFactory
     */
    private $jwsVerifierFactory;

    /**
     * @var null|Serializer\JWSSerializerManagerFactory
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var null|Serializer\JWSSerializerManager
     */
    private $jwsSerializerManager;

    /**
     * @var JWSLoaderFactory
     */
    private $jwsLoaderFactory;

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory->add('HS256', new Algorithm\HS256());
            $this->algorithmManagerFactory->add('HS384', new Algorithm\HS384());
            $this->algorithmManagerFactory->add('HS512', new Algorithm\HS512());
            $this->algorithmManagerFactory->add('ES256', new Algorithm\ES256());
            $this->algorithmManagerFactory->add('ES384', new Algorithm\ES384());
            $this->algorithmManagerFactory->add('ES512', new Algorithm\ES512());
            $this->algorithmManagerFactory->add('RS256', new Algorithm\RS256());
            $this->algorithmManagerFactory->add('RS384', new Algorithm\RS384());
            $this->algorithmManagerFactory->add('RS512', new Algorithm\RS512());
            $this->algorithmManagerFactory->add('PS256', new Algorithm\PS256());
            $this->algorithmManagerFactory->add('PS384', new Algorithm\PS384());
            $this->algorithmManagerFactory->add('PS512', new Algorithm\PS512());
            $this->algorithmManagerFactory->add('none', new Algorithm\None());
            $this->algorithmManagerFactory->add('EdDSA', new Algorithm\EdDSA());
        }

        return $this->algorithmManagerFactory;
    }

    protected function getJWSBuilderFactory(): JWSBuilderFactory
    {
        if (null === $this->jwsBuilderFactory) {
            $this->jwsBuilderFactory = new JWSBuilderFactory(
                $this->getAlgorithmManagerFactory()
            );
        }

        return $this->jwsBuilderFactory;
    }

    protected function getJWSVerifierFactory(): JWSVerifierFactory
    {
        if (null === $this->jwsVerifierFactory) {
            $this->jwsVerifierFactory = new JWSVerifierFactory(
                $this->getAlgorithmManagerFactory()
            );
        }

        return $this->jwsVerifierFactory;
    }

    protected function getJWSSerializerManagerFactory(): Serializer\JWSSerializerManagerFactory
    {
        if (null === $this->jwsSerializerManagerFactory) {
            $this->jwsSerializerManagerFactory = new Serializer\JWSSerializerManagerFactory();
            $this->jwsSerializerManagerFactory->add(new Serializer\CompactSerializer());
            $this->jwsSerializerManagerFactory->add(new Serializer\JSONFlattenedSerializer());
            $this->jwsSerializerManagerFactory->add(new Serializer\JSONGeneralSerializer());
        }

        return $this->jwsSerializerManagerFactory;
    }

    protected function getJWSSerializerManager(): Serializer\JWSSerializerManager
    {
        if (null === $this->jwsSerializerManager) {
            $this->jwsSerializerManager = new Serializer\JWSSerializerManager([
                new Serializer\CompactSerializer(),
                new Serializer\JSONFlattenedSerializer(),
                new Serializer\JSONGeneralSerializer(),
            ]);
        }

        return $this->jwsSerializerManager;
    }

    protected function getJWSLoaderFactory(): JWSLoaderFactory
    {
        if (null === $this->jwsLoaderFactory) {
            $this->jwsLoaderFactory = new JWSLoaderFactory(
                $this->getJWSSerializerManagerFactory(),
                $this->getJWSVerifierFactory(),
                null
            );
        }

        return $this->jwsLoaderFactory;
    }
}
