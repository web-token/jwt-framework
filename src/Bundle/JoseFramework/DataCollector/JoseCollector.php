<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimCheckerManagerFactory;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Core\Algorithm;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithm;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithm;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Jose\Component\KeyManagement\KeyAnalyzer\KeyAnalyzerManager;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\JWSSerializerManagerFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

final class JoseCollector extends DataCollector
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory|null
     */
    private $compressionMethodManagerFactory;

    /**
     * @var JWSSerializerManagerFactory|null
     */
    private $jwsSerializerManagerFactory;

    /**
     * @var JWESerializerManagerFactory|null
     */
    private $jweSerializerManagerFactory;

    /**
     * @var KeyAnalyzerManager|null
     */
    private $jwkAnalyzerManager;

    /**
     * @var ClaimCheckerManagerFactory|null
     */
    private $claimCheckerManagerFactory;

    /**
     * @var HeaderCheckerManagerFactory|null
     */
    private $headerCheckerManagerFactory;

    /**
     * JoseCollector constructor.
     *
     * @param AlgorithmManagerFactory              $algorithmManagerFactory
     * @param CompressionMethodManagerFactory|null $compressionMethodManagerFactory
     * @param JWSSerializerManagerFactory|null     $jwsSerializerManagerFactory
     * @param JWESerializerManagerFactory|null     $jweSerializerManagerFactory
     * @param KeyAnalyzerManager|null              $jwkAnalyzerManager
     * @param ClaimCheckerManagerFactory|null      $claimCheckerManagerFactory
     * @param HeaderCheckerManagerFactory|null     $headerCheckerManagerFactory
     */
    public function __construct(
        AlgorithmManagerFactory $algorithmManagerFactory,
        ?CompressionMethodManagerFactory $compressionMethodManagerFactory = null,
        ?JWSSerializerManagerFactory $jwsSerializerManagerFactory = null,
        ?JWESerializerManagerFactory $jweSerializerManagerFactory = null,
        ?KeyAnalyzerManager $jwkAnalyzerManager = null,
        ?ClaimCheckerManagerFactory $claimCheckerManagerFactory = null,
        ?HeaderCheckerManagerFactory $headerCheckerManagerFactory = null
    ) {
        $this->data = [];
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
        $this->jwsSerializerManagerFactory = $jwsSerializerManagerFactory;
        $this->jweSerializerManagerFactory = $jweSerializerManagerFactory;
        $this->jwkAnalyzerManager = $jwkAnalyzerManager;
        $this->claimCheckerManagerFactory = $claimCheckerManagerFactory;
        $this->headerCheckerManagerFactory = $headerCheckerManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, \Exception $exception = null)
    {
        $this->collectSupportedAlgorithms();
        $this->collectSupportedHeaderCheckers();
        $this->collectSupportedClaimCheckers();
        $this->collectSupportedCompressionMethods();
        $this->collectSupportedJWSSerializations();
        $this->collectSupportedJWESerializations();
        $this->collectSupportedJWSBuilders();
        $this->collectSupportedJWSVerifiers();
        $this->collectSupportedJWEBuilders();
        $this->collectSupportedJWEDecrypters();
        $this->collectJWK();
        $this->collectJWKSet();
    }

    /**
     * @return array
     */
    public function getAlgorithmDetails(): array
    {
        return $this->data['algorithms'];
    }

    /**
     * @return int
     */
    public function countSignatureAlgorithms(): int
    {
        return $this->data['types']['signature'];
    }

    /**
     * @return int
     */
    public function countKeyEncryptionAlgorithms(): int
    {
        return $this->data['types']['key_encryption'];
    }

    /**
     * @return int
     */
    public function countContentEncryptionAlgorithms(): int
    {
        return $this->data['types']['content_encryption'];
    }

    /**
     * @return array
     */
    public function getCompressionMethodDetails(): array
    {
        return $this->data['compression_methods'];
    }

    /**
     * @return array
     */
    public function getJWSSerializationDetails(): array
    {
        return $this->data['jws_serialization'];
    }

    /**
     * @return array
     */
    public function getJWESerializationDetails(): array
    {
        return $this->data['jwe_serialization'];
    }

    /**
     * @return array
     */
    public function getJWKs(): array
    {
        return $this->data['jwk'];
    }

    /**
     * @return array
     */
    public function getJWKSets(): array
    {
        return $this->data['jwkset'];
    }

    /**
     * @return array
     */
    public function getJWSBuilders(): array
    {
        return $this->data['jws_builders'];
    }

    /**
     * @return array
     */
    public function getJWSVerifiers(): array
    {
        return $this->data['jws_verifiers'];
    }

    /**
     * @return array
     */
    public function getJWEBuilders(): array
    {
        return $this->data['jwe_builders'];
    }

    /**
     * @return array
     */
    public function getJWEDecrypters(): array
    {
        return $this->data['jwe_decrypters'];
    }

    /**
     * @return array
     */
    public function getHeaderCheckers(): array
    {
        return $this->data['header_checkers'];
    }

    /**
     * @return array
     */
    public function getHeaderCheckerManagers(): array
    {
        return $this->headerCheckerManagers;
    }

    /**
     * @return array
     */
    public function getClaimCheckers(): array
    {
        return $this->data['claim_checkers'];
    }

    /**
     * @return array
     */
    public function getClaimCheckerManagers(): array
    {
        return $this->claimCheckerManagers;
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'jose_collector';
    }

    private function collectSupportedHeaderCheckers()
    {
        $this->data['header_checkers'] = [];
        if (null !== $this->headerCheckerManagerFactory) {
            $aliases = $this->headerCheckerManagerFactory->all();
            foreach ($aliases as $alias => $checker) {
                $this->data['header_checkers'][$alias] = [
                    'header' => $checker->supportedHeader(),
                    'protected' => $checker->protectedHeaderOnly(),
                ];
            }
        }
    }

    private function collectSupportedClaimCheckers()
    {
        $this->data['claim_checkers'] = [];
        if (null !== $this->headerCheckerManagerFactory) {
            $aliases = $this->claimCheckerManagerFactory->all();
            foreach ($aliases as $alias => $checker) {
                $this->data['claim_checkers'][$alias] = [
                    'claim' => $checker->supportedClaim(),
                ];
            }
        }
    }

    private function collectSupportedAlgorithms()
    {
        $algorithms = $this->algorithmManagerFactory->all();
        $this->data['algorithms'] = [];
        $signatureAlgorithms = 0;
        $keyEncryptionAlgorithms = 0;
        $contentEncryptionAlgorithms = 0;
        foreach ($algorithms as $alias => $algorithm) {
            $type = $this->getAlgorithmType($algorithm, $signatureAlgorithms, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms);
            if (!array_key_exists($type, $this->data['algorithms'])) {
                $this->data['algorithms'][$type] = [];
            }
            $this->data['algorithms'][$type][$alias] = [
                'name' => $algorithm->name(),
            ];
        }

        $this->data['types'] = [
            'signature' => $signatureAlgorithms,
            'key_encryption' => $keyEncryptionAlgorithms,
            'content_encryption' => $contentEncryptionAlgorithms,
        ];
    }

    /**
     * @param Algorithm $algorithm
     * @param int       $signatureAlgorithms
     * @param int       $keyEncryptionAlgorithms
     * @param int       $contentEncryptionAlgorithms
     *
     * @return string
     */
    private function getAlgorithmType(Algorithm $algorithm, int &$signatureAlgorithms, int &$keyEncryptionAlgorithms, int &$contentEncryptionAlgorithms): string
    {
        switch (true) {
            case $algorithm instanceof SignatureAlgorithm:
                $signatureAlgorithms++;

                return 'Signature';
            case $algorithm instanceof KeyEncryptionAlgorithm:
                $keyEncryptionAlgorithms++;

                return 'Key Encryption';
            case $algorithm instanceof ContentEncryptionAlgorithm:
                $contentEncryptionAlgorithms++;

                return 'Content Encryption';
            default:
                return 'Unknown';
        }
    }

    private function collectSupportedCompressionMethods()
    {
        $this->data['compression_methods'] = [];
        if (null === $this->compressionMethodManagerFactory) {
            return;
        }
        $compressionMethods = $this->compressionMethodManagerFactory->all();
        foreach ($compressionMethods as $alias => $compressionMethod) {
            $this->data['compression_methods'][$alias] = $compressionMethod->name();
        }
    }

    private function collectSupportedJWSSerializations()
    {
        $this->data['jws_serialization'] = [];
        if (null === $this->jwsSerializerManagerFactory) {
            return;
        }
        $serializers = $this->jwsSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $this->data['jws_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }

    private function collectSupportedJWESerializations()
    {
        $this->data['jwe_serialization'] = [];
        if (null === $this->jweSerializerManagerFactory) {
            return;
        }
        $serializers = $this->jweSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $this->data['jwe_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }

    private function collectSupportedJWSBuilders()
    {
        $this->data['jws_builders'] = [];
        foreach ($this->jwsBuilders as $id => $jwsBuilder) {
            $this->data['jws_builders'][$id] = [
                'signature_algorithms' => $jwsBuilder->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    private function collectSupportedJWSVerifiers()
    {
        $this->data['jws_verifiers'] = [];
        foreach ($this->jwsVerifiers as $id => $jwsVerifier) {
            $this->data['jws_verifiers'][$id] = [
                'signature_algorithms' => $jwsVerifier->getSignatureAlgorithmManager()->list(),
            ];
        }
    }

    private function collectSupportedJWEBuilders()
    {
        $this->data['jwe_builders'] = [];
        foreach ($this->jweBuilders as $id => $jweBuilder) {
            $this->data['jwe_builders'][$id] = [
                'key_encryption_algorithms' => $jweBuilder->getKeyEncryptionAlgorithmManager()->list(),
                'content_encryption_algorithms' => $jweBuilder->getContentEncryptionAlgorithmManager()->list(),
                'compression_methods' => $jweBuilder->getCompressionMethodManager()->list(),
            ];
        }
    }

    private function collectSupportedJWEDecrypters()
    {
        $this->data['jwe_decrypters'] = [];
        foreach ($this->jweDecrypters as $id => $jweDecrypter) {
            $this->data['jwe_decrypters'][$id] = [
                'key_encryption_algorithms' => $jweDecrypter->getKeyEncryptionAlgorithmManager()->list(),
                'content_encryption_algorithms' => $jweDecrypter->getContentEncryptionAlgorithmManager()->list(),
                'compression_methods' => $jweDecrypter->getCompressionMethodManager()->list(),
            ];
        }
    }

    private function collectJWK()
    {
        $this->data['jwk'] = [];
        foreach ($this->jwks as $id => $jwk) {
            $this->data['jwk'][$id] = [
                'jwk' => $jwk,
                'analyze' => null === $this->jwkAnalyzerManager ? [] : $this->jwkAnalyzerManager->analyze($jwk),
            ];
        }
    }

    private function collectJWKSet()
    {
        $this->data['jwkset'] = [];
        foreach ($this->jwksets as $id => $jwkset) {
            $analyze = [];
            if (null !== $this->jwkAnalyzerManager) {
                foreach ($jwkset as $kid => $jwk) {
                    $analyze[$kid] = $this->jwkAnalyzerManager->analyze($jwk);
                }
            }
            $this->data['jwkset'][$id] = [
                'jwkset' => $jwkset,
                'analyze' => $analyze,
            ];
        }
    }

    /**
     * @var HeaderCheckerManager[]
     */
    private $headerCheckerManagers = [];

    /**
     * @param string               $id
     * @param HeaderCheckerManager $headerCheckerManager
     */
    public function addHeaderCheckerManager(string $id, HeaderCheckerManager $headerCheckerManager)
    {
        $this->headerCheckerManagers[$id] = $headerCheckerManager;
    }

    /**
     * @var ClaimCheckerManager[]
     */
    private $claimCheckerManagers = [];

    /**
     * @param string              $id
     * @param ClaimCheckerManager $claimCheckerManager
     */
    public function addClaimCheckerManager(string $id, ClaimCheckerManager $claimCheckerManager)
    {
        $this->claimCheckerManagers[$id] = $claimCheckerManager;
    }

    /**
     * @var JWSBuilder[]
     */
    private $jwsBuilders = [];

    /**
     * @param string     $id
     * @param JWSBuilder $jwsBuilder
     */
    public function addJWSBuilder(string $id, JWSBuilder $jwsBuilder)
    {
        $this->jwsBuilders[$id] = $jwsBuilder;
    }

    /**
     * @var JWSVerifier[]
     */
    private $jwsVerifiers = [];

    /**
     * @param string      $id
     * @param JWSVerifier $jwsVerifier
     */
    public function addJWSVerifier(string $id, JWSVerifier $jwsVerifier)
    {
        $this->jwsVerifiers[$id] = $jwsVerifier;
    }

    /**
     * @var JWEBuilder[]
     */
    private $jweBuilders = [];

    /**
     * @param string     $id
     * @param JWEBuilder $jweBuilder
     */
    public function addJWEBuilder(string $id, JWEBuilder $jweBuilder)
    {
        $this->jweBuilders[$id] = $jweBuilder;
    }

    /**
     * @var JWEDecrypter[]
     */
    private $jweDecrypters = [];

    /**
     * @param string       $id
     * @param JWEDecrypter $jweDecrypter
     */
    public function addJWEDecrypter(string $id, JWEDecrypter $jweDecrypter)
    {
        $this->jweDecrypters[$id] = $jweDecrypter;
    }

    /**
     * @var JWK[]
     */
    private $jwks = [];

    /**
     * @param string $id
     * @param JWK    $jwk
     */
    public function addJWK(string $id, JWK $jwk)
    {
        $this->jwks[$id] = $jwk;
    }

    /**
     * @var JWKSet[]
     */
    private $jwksets = [];

    /**
     * @param string $id
     * @param JWKSet $jwkset
     */
    public function addJWKSet(string $id, JWKSet $jwkset)
    {
        $this->jwksets[$id] = $jwkset;
    }
}
