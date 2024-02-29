<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\EnvVarProcessor;

use Closure;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Override;
use RuntimeException;
use Symfony\Component\DependencyInjection\EnvVarProcessorInterface;

final readonly class KeyEnvVarProcessor implements EnvVarProcessorInterface
{
    #[Override]
    public function getEnv(string $prefix, string $name, Closure $getEnv): mixed
    {
        $env = $getEnv($name);

        return match ($prefix) {
            'jwk' => JWK::createFromJson($env),
            'jwkset' => JWKSet::createFromJson($env),
            default => throw new RuntimeException(sprintf('Unsupported prefix "%s".', $prefix)),
        };
    }

    #[Override]
    public static function getProvidedTypes(): array
    {
        return [
            'jwk' => 'string',
            'jwkset' => 'string',
        ];
    }
}
