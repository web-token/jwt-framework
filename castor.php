<?php

declare(strict_types=1);

use Castor\Attribute\AsTask;
use function Castor\io;
use function Castor\run;

#[AsTask(description: 'Run mutation testing')]
function infect(int $minMsi = 0, int $minCoveredMsi = 0, bool $ci = false): void
{
    io()->title('Running infection');
    $nproc = run('nproc', quiet: true);
    if (! $nproc->isSuccessful()) {
        io()->error('Cannot determine the number of processors');
        return;
    }
    $threads = (int) $nproc->getOutput();
    $command = [
        'php',
        'vendor/bin/infection',
        sprintf('--min-msi=%s', $minMsi),
        sprintf('--min-covered-msi=%s', $minCoveredMsi),
        sprintf('--threads=%s', $threads),
    ];
    if ($ci) {
        $command[] = '--logger-github';
        $command[] = '-s';
    }
    $environment = [
        'XDEBUG_MODE' => 'coverage',
    ];
    run($command, environment: $environment);
}

#[AsTask(description: 'Run tests')]
function test(bool $coverageHtml = false, bool $coverageText = false, null|string $group = null): void
{
    io()->title('Running tests');
    $command = ['php', 'vendor/bin/phpunit', '--color'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    if ($coverageHtml) {
        $command[] = '--coverage-html=build/coverage';
        $environment['XDEBUG_MODE'] = 'coverage';
    }
    if ($coverageText) {
        $command[] = '--coverage-text';
        $environment['XDEBUG_MODE'] = 'coverage';
    }
    if ($group !== null) {
        $command[] = sprintf('--group=%s', $group);
    }
    run($command, environment: $environment);
}

#[AsTask(description: 'Coding standards check')]
function cs(
    #[\Castor\Attribute\AsOption(description: 'Fix issues if possible')]
    bool $fix = false,
    #[\Castor\Attribute\AsOption(description: 'Clear cache')]
    bool $clearCache = false
): void {
    io()->title('Running coding standards check');
    $command = ['php', 'vendor/bin/ecs', 'check'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    if ($fix) {
        $command[] = '--fix';
    }
    if ($clearCache) {
        $command[] = '--clear-cache';
    }
    run($command, environment: $environment);
}

#[AsTask(description: 'Running PHPStan')]
function stan(): void
{
    io()->title('Running PHPStan');
    $command = ['php', 'vendor/bin/phpstan', 'analyse'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    run($command, environment: $environment);
}

#[AsTask(description: 'Validate Composer configuration')]
function validate(): void
{
    io()->title('Validating Composer configuration');
    $command = ['composer', 'validate', '--strict'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    run($command, environment: $environment);

    $command = ['composer', 'dump-autoload', '--optimize', '--strict-psr'];
    run($command, environment: $environment);
}

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses')]
function checkLicenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0']
): void {
    io()->title('Checking licenses');
    $allowedExceptions = [];
    $command = ['composer', 'licenses', '-f', 'json'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    $result = run($command, environment: $environment, quiet: true);
    if (! $result->isSuccessful()) {
        io()->error('Cannot determine licenses');
        exit(1);
    }
    $licenses = json_decode($result->getOutput(), true);
    $disallowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => ! in_array($name, $allowedExceptions, true)
            && count(array_diff($info['license'], $allowedLicenses)) === 1,
        \ARRAY_FILTER_USE_BOTH
    );
    $allowed = array_filter(
        $licenses['dependencies'],
        static fn (array $info, $name) => in_array($name, $allowedExceptions, true)
            || count(array_diff($info['license'], $allowedLicenses)) === 0,
        \ARRAY_FILTER_USE_BOTH
    );
    if (count($disallowed) > 0) {
        io()
            ->table(
                ['Package', 'License'],
                array_map(
                    static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                    array_keys($disallowed),
                    $disallowed
                )
            );
        io()
            ->error('Disallowed licenses found');
        exit(1);
    }
    io()
        ->table(
            ['Package', 'License'],
            array_map(
                static fn ($name, $info) => [$name, implode(', ', $info['license'])],
                array_keys($allowed),
                $allowed
            )
        );
    io()
        ->success('All licenses are allowed');
}

#[AsTask(description: 'Run Rector')]
function rector(
    #[\Castor\Attribute\AsOption(description: 'Fix issues if possible')]
    bool $fix = false,
    #[\Castor\Attribute\AsOption(description: 'Clear cache')]
    bool $clearCache = false
): void {
    io()->title('Running Rector');
    $command = ['php', 'vendor/bin/rector', 'process', '--ansi'];
    if (! $fix) {
        $command[] = '--dry-run';
    }
    if ($clearCache) {
        $command[] = '--clear-cache';
    }
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    run($command, environment: $environment);
}

#[AsTask(description: 'Run Rector')]
function deptrac(): void
{
    io()->title('Running Rector');
    $command = ['php', 'vendor/bin/deptrac', 'analyse', '--fail-on-uncovered', '--no-cache'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    run($command, environment: $environment);
}

#[AsTask(description: 'Run Linter')]
function lint(): void
{
    io()->title('Running Linter');
    $command = ['composer', 'exec', '--', 'parallel-lint', __DIR__ . '/src/', __DIR__ . '/tests/'];
    $environment = [
        'XDEBUG_MODE' => 'off',
    ];
    run($command, environment: $environment);
}
