<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DataCollector;

use Closure;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Override;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;

/**
 * The keys and key sets of the bundle are registered as closures and only created when the data is collected. The
 * collector itself is created with the profiler, on every request: creating them at that point would make every
 * request fail as soon as one of them cannot be loaded, whether the application uses it or not.
 */
final class KeyCollector implements Collector
{
    /**
     * @var array<string, Closure(): JWK>
     */
    private array $jwks = [];

    /**
     * @var array<string, Closure(): JWKSet>
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
    #[Override]
    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->collectJWK($data);
        $this->collectJWKSet($data);
    }

    public function addJWK(string $id, JWK $jwk): void
    {
        $this->jwks[$id] = static fn (): JWK => $jwk;
    }

    public function addJWKSet(string $id, JWKSet $jwkset): void
    {
        $this->jwksets[$id] = static fn (): JWKSet => $jwkset;
    }

    /**
     * Registers a key that the given closure creates when the data is collected.
     *
     * @param Closure(): JWK $jwk
     *
     * @internal
     */
    public function addLazyJWK(string $id, Closure $jwk): void
    {
        $this->jwks[$id] = $jwk;
    }

    /**
     * Registers a key set that the given closure creates when the data is collected.
     *
     * @param Closure(): JWKSet $jwkset
     *
     * @internal
     */
    public function addLazyJWKSet(string $id, Closure $jwkset): void
    {
        $this->jwksets[$id] = $jwkset;
    }

    /**
     * A key that cannot be created or analyzed is reported with the error raised, and the other keys are collected.
     *
     * @param array<string, array<string, mixed>> $data
     */
    private function collectJWK(array &$data): void
    {
        $cloner = new VarCloner();
        $data['key']['jwk'] = [];
        foreach ($this->jwks as $id => $createJWK) {
            try {
                $jwk = $createJWK();
                $data['key']['jwk'][$id] = [
                    'jwk' => $cloner->cloneVar($jwk),
                    'analyze' => $this->jwkAnalyzerManager?->analyze($jwk) ?? [],
                ];
            } catch (Throwable $throwable) {
                $data['key']['jwk'][$id] = self::failure($throwable);
            }
        }
    }

    /**
     * A key set that cannot be created or analyzed is reported with the error raised, and the other key sets are
     * collected.
     *
     * @param array<string, array<string, mixed>> $data
     */
    private function collectJWKSet(array &$data): void
    {
        $cloner = new VarCloner();
        $data['key']['jwkset'] = [];
        foreach ($this->jwksets as $id => $createJWKSet) {
            try {
                $jwkset = $createJWKSet();
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
            } catch (Throwable $throwable) {
                $data['key']['jwkset'][$id] = self::failure($throwable);
            }
        }
    }

    /**
     * Only the class and the message of the error are kept: the profile is serialized, and the trace of an error
     * carries the arguments of the calls that led to it.
     *
     * @return array{error: array{class: class-string<Throwable>, message: string}}
     */
    private static function failure(Throwable $throwable): array
    {
        return [
            'error' => [
                'class' => $throwable::class,
                'message' => $throwable->getMessage(),
            ],
        ];
    }
}
