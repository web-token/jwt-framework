<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Tests;

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\Converter\StandardConverter;
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

    protected function getAlgorithmManagerFactory(): AlgorithmManagerFactory
    {
        if (null === $this->algorithmManagerFactory) {
            $this->algorithmManagerFactory = new AlgorithmManagerFactory();
            $this->algorithmManagerFactory
                ->add('HS256', new Algorithm\HS256())
                ->add('HS384', new Algorithm\HS384())
                ->add('HS512', new Algorithm\HS512())
                ->add('ES256', new Algorithm\ES256())
                ->add('ES384', new Algorithm\ES384())
                ->add('ES512', new Algorithm\ES512())
                ->add('RS256', new Algorithm\RS256())
                ->add('RS384', new Algorithm\RS384())
                ->add('RS512', new Algorithm\RS512())
                ->add('PS256', new Algorithm\PS256())
                ->add('PS384', new Algorithm\PS384())
                ->add('PS512', new Algorithm\PS512())
                ->add('none', new Algorithm\None())
                ->add('EdDSA', new Algorithm\EdDSA());
        }

        return $this->algorithmManagerFactory;
    }

    /**
     * @var JWSBuilderFactory
     */
    private $jwsBuilderFactory;

    protected function getJWSBuilderFactory(): JWSBuilderFactory
    {
        if (null === $this->jwsBuilderFactory) {
            $this->jwsBuilderFactory = new JWSBuilderFactory(
                new StandardConverter(),
                $this->getAlgorithmManagerFactory()
            );
        }

        return $this->jwsBuilderFactory;
    }

    /**
     * @var JWSVerifierFactory
     */
    private $jwsVerifierFactory;

    protected function getJWSVerifierFactory(): JWSVerifierFactory
    {
        if (null === $this->jwsVerifierFactory) {
            $this->jwsVerifierFactory = new JWSVerifierFactory(
                $this->getAlgorithmManagerFactory()
            );
        }

        return $this->jwsVerifierFactory;
    }

    /**
     * @var Serializer\JWSSerializerManagerFactory|null
     */
    private $jwsSerializerManagerFactory = null;

    protected function getJWSSerializerManagerFactory(): Serializer\JWSSerializerManagerFactory
    {
        if (null === $this->jwsSerializerManagerFactory) {
            $this->jwsSerializerManagerFactory = new Serializer\JWSSerializerManagerFactory();
            $this->jwsSerializerManagerFactory->add(new Serializer\CompactSerializer(new StandardConverter()));
            $this->jwsSerializerManagerFactory->add(new Serializer\JSONFlattenedSerializer(new StandardConverter()));
            $this->jwsSerializerManagerFactory->add(new Serializer\JSONGeneralSerializer(new StandardConverter()));
        }

        return $this->jwsSerializerManagerFactory;
    }

    /**
     * @var Serializer\JWSSerializerManager|null
     */
    private $jwsSerializerManager = null;

    protected function getJWSSerializerManager(): Serializer\JWSSerializerManager
    {
        if (null === $this->jwsSerializerManager) {
            $this->jwsSerializerManager = Serializer\JWSSerializerManager::create([
                new Serializer\CompactSerializer(new StandardConverter()),
                new Serializer\JSONFlattenedSerializer(new StandardConverter()),
                new Serializer\JSONGeneralSerializer(new StandardConverter()),
            ]);
        }

        return $this->jwsSerializerManager;
    }

    /**
     * @var JWSLoaderFactory
     */
    private $jwsLoaderFactory;

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
