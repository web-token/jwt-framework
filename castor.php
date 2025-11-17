<?php

declare(strict_types=1);

use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\guard_min_version;
use function Castor\io;
use function Castor\notify;
use function Castor\run;

guard_min_version('v0.23.0');

/**
 * @param array<string> $allowedLicenses
 */
#[AsTask(description: 'Check licenses.')]
function checkLicenses(
    array $allowedLicenses = ['Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MIT', 'MPL-2.0', 'OSL-3.0']
): void {
    io()->title('Checking licenses');
    $allowedExceptions = [];
    $command = ['composer', 'licenses', '-f', 'json'];
    $context = context();
    $context->withEnvironment([
        'XDEBUG_MODE' => 'off',
    ]);
    $context->withQuiet();
    $result = run($command, context: $context);
    if (! $result->isSuccessful()) {
        io()->error('Cannot determine licenses');
        exit(1);
    }
    $licenses = json_decode((string) $result->getOutput(), true);
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

#[AsTask(description: 'Restart the containers.')]
function restart(): void
{
    stop();
    start();
}

#[AsTask(description: 'Clean the infrastructure (remove container, volume, networks).')]
function destroy(bool $force = false): void
{
    if (! $force) {
        io()->warning('This will permanently remove all containers, volumes, networks... created for this project.');
        io()
            ->comment('You can use the --force option to avoid this confirmation.');

        if (! io()->confirm('Are you sure?', false)) {
            io()->comment('Aborted.');

            return;
        }
    }

    run('docker-compose down -v --remove-orphans --volumes --rmi=local');
    notify('The infrastructure has been destroyed.');
}

#[AsTask(description: 'Stops and removes the containers.')]
function stop(): void
{
    run(['docker', 'compose', 'down']);
}

#[AsTask(description: 'Starts the containers.')]
function start(): void
{
    run(['docker', 'compose', 'up', '-d']);
    frontend();
}

#[AsTask(description: 'Build the images.')]
function build(): void
{
    run(['docker', 'compose', 'build', '--no-cache', '--pull']);
}

#[AsTask(description: 'Compile the frontend.')]
function frontend(): void
{
    $consoleOutput = run(['bin/console'], context: context()->withQuiet());
    $commandsToRun = [
        'assets:install' => [],
        'importmap:install' => [],
        //'tailwind:build' => ['--watch'],
    ];

    foreach ($commandsToRun as $command => $arguments) {
        if (str_contains((string) $consoleOutput->getOutput(), $command)) {
            php(['bin/console', $command, ...$arguments]);
        }
    }
}

#[AsTask(description: 'Update the dependencies and other features.')]
function update(): void
{
    run(['composer', 'update']);
    $consoleOutput = run(['bin/console'], context: context()->withQuiet());
    $commandsToRun = [
        'doctrine:migrations:migrate' => [],
        'doctrine:schema:validate' => [],
        'doctrine:fixtures:load' => [],
        'geoip2:update' => [],
        'app:browscap:update' => [],
        'importmap:update' => [],
    ];

    foreach ($commandsToRun as $command => $arguments) {
        if (str_contains((string) $consoleOutput->getOutput(), $command)) {
            php(['bin/console', $command, ...$arguments]);
        }
    }
}

#[AsTask(description: 'Runs a Consumer from the Docket Container.')]
function consume(): void
{
    php(['bin/console', 'messenger:consume', '--all']);
}

#[AsTask(description: 'Runs a Symfony Console command from the Docket Container.', ignoreValidationErrors: true)]
function console(#[AsRawTokens] array $args = []): void
{
    php(['bin/console', ...$args]);
}

#[AsTask(description: 'Runs a PHP command from the Docket Container.', ignoreValidationErrors: true)]
function php(#[AsRawTokens] array $args = []): void
{
    run(['docker', 'compose', 'exec', '-T', 'php', ...$args]);
}

function phpqa(array $command, array $dockerOptions = []): void
{
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim((string) shell_exec('command -v docker')) !== '';

    if (! $hasDocker || $inContainer) {
        run($command);
        return;
    }

    if (! is_dir('tmp-phpqa')) {
        mkdir('tmp-phpqa', 0777, true);
        chown('tmp-phpqa', 1000);
        chgrp('tmp-phpqa', 1000);
    }

    $defaultDockerOptions = [
        '--rm',
        '--init',
        '-it',
        '--user', sprintf('%s:%s', getmyuid(), getmygid()),
        '--pull', 'always',
        '-v', getcwd() . ':/project',
        '-v', getcwd() . '/tmp-phpqa:/tmp',
        '-w', '/project',
        '-e', 'XDEBUG_MODE=off',
    ];

    $phpVersion = (getenv('PHP_VERSION') ?: \PHP_MAJOR_VERSION . '.' . \PHP_MINOR_VERSION)
            ?: '8.4';

    run([
        'docker', 'run',
        ...$defaultDockerOptions,
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', $phpVersion),
        ...$command,
    ]);
}

#[AsTask(description: 'Run PHPUnit tests with coverage')]
function phpunit(): void
{
    phpqa(
        [
            'composer', 'exec', '--', 'phpunit-11',
            '--coverage-xml', '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration', '.ci-tools/phpunit.xml.dist',
        ],
        ['-e', 'XDEBUG_MODE=coverage'] // Docker options supplémentaires
    );
}

#[AsTask(description: 'Run Easy Coding Standard')]
function ecs(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php']);
}

#[AsTask(description: 'Fix coding style with Easy Coding Standard')]
function ecs_fix(): void
{
    phpqa(['composer', 'exec', '--', 'ecs', 'check', '--config', '.ci-tools/ecs.php', '--fix']);
}

#[AsTask(description: 'Run Rector dry-run')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run PHPStan')]
function phpstan(): void
{
    phpqa(
        [
            'composer', 'exec', '--', 'phpstan', 'analyse', '--error-format=github', '--configuration=.ci-tools/phpstan.neon']
    );
}

#[AsTask(description: 'Generate PHPStan baseline')]
function phpstan_baseline(): void
{
    phpqa([
        'composer', 'exec', '--', 'phpstan', 'analyse',
        '--configuration=.ci-tools/phpstan.neon',
        '--generate-baseline=.ci-tools/phpstan-baseline.neon',
    ]);
}

#[AsTask(description: 'Run Deptrac')]
function deptrac(): void
{
    phpqa([
        'composer', 'exec', '--', 'deptrac',
        '--config-file', '.ci-tools/deptrac.yaml',
        '--report-uncovered',
        '--report-skipped',
        '--fail-on-uncovered',
    ]);
}

#[AsTask(description: 'Install the dependencies')]
function install(bool $lowest = false): void
{
    $command = ['composer', 'install'];
    if ($lowest) {
        $command[] = '--prefer-lowest';
    }
    phpqa($command);
}

#[AsTask(description: 'Run PHP parallel linter')]
function lint(): void
{
    phpqa(['composer', 'exec', '--', 'parallel-lint', 'src', 'tests']);
}

#[AsTask(description: 'Run Infection for mutation testing')]
function infect($minMsi = 0, $minCoveredMsi = 0): void
{
    phpqa([
        'composer', 'exec', '--', 'infection',
        '--coverage=coverage',
        sprintf('--min-msi=%d', $minMsi),
        sprintf('--min-covered-msi=%d', $minCoveredMsi),
        '--threads=max',
        '--logger-github',
        '-s',
        '--filter=src/',
        '--configuration=.ci-tools/infection.json.dist',
    ], ['-e', 'XDEBUG_MODE=coverage']);
}

#[AsTask(description: 'Run QA command', ignoreValidationErrors: true)]
function qa(#[AsRawTokens] array $args = []): void
{
    phpqa(['composer', 'exec', '--', ...$args]);
}
