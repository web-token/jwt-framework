<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;

class KeyCollector implements Collector
{
    /**
     * @var array<JWK>
     */
    private array $jwks = [];

    /**
     * @var array<JWKSet>
     */
    private array $jwksets = [];

    public function __construct(
        private readonly ?KeyAnalyzerManager $jwkAnalyzerManager = null,
        private readonly ?KeysetAnalyzerManager $jwksetAnalyzerManager = null
    ) {
    }

    /**
     * @param array<string, mixed> $data
     */
    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->collectJWK($data);
        $this->collectJWKSet($data);
    }

    public function addJWK(string $id, JWK $jwk): void
    {
        $this->jwks[$id] = $jwk;
    }

    public function addJWKSet(string $id, JWKSet $jwkset): void
    {
        $this->jwksets[$id] = $jwkset;
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectJWK(array &$data): void
    {
        $cloner = new VarCloner();
        $data['key']['jwk'] = [];
        foreach ($this->jwks as $id => $jwk) {
            $data['key']['jwk'][$id] = [
                'jwk' => $cloner->cloneVar($jwk),
                'analyze' => $this->jwkAnalyzerManager === null ? [] : $this->jwkAnalyzerManager->analyze($jwk),
            ];
        }
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectJWKSet(array &$data): void
    {
        $cloner = new VarCloner();
        $data['key']['jwkset'] = [];
        foreach ($this->jwksets as $id => $jwkset) {
            $analyze = [];
            $analyzeJWKSet = new MessageBag();
            if ($this->jwkAnalyzerManager !== null) {
                foreach ($jwkset as $kid => $jwk) {
                    $analyze[$kid] = $this->jwkAnalyzerManager->analyze($jwk);
                }
            }
            if ($this->jwksetAnalyzerManager !== null) {
                $analyzeJWKSet = $this->jwksetAnalyzerManager->analyze($jwkset);
            }
            $data['key']['jwkset'][$id] = [
                'jwkset' => $cloner->cloneVar($jwkset),
                'analyze' => $analyze,
                'analyze_jwkset' => $analyzeJWKSet,
            ];
        }
    }
}
