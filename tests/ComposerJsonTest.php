<?php

declare(strict_types=1);

namespace Jose;

use DirectoryIterator;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Traversable;
use const JSON_THROW_ON_ERROR;

/**
 * @internal
 * @note Courtesy of @scheb
 *
 * @see https://github.com/scheb/2fa/commit/94ff439212f465d8c9d146bf87d82ca32c4c4cbc#commitcomment-41153585
 */
final class ComposerJsonTest extends TestCase
{
    private const string SRC_DIR = __DIR__ . '/../src';

    #[Test]
    public function packageDependenciesEqualRootDependencies(): void
    {
        $usedDependencies = ['symfony/symfony']; // Some builds add this to composer.json
        $rootDependencies = $this->getComposerDependencies(__DIR__ . '/../composer.json');

        foreach ($this->listSubPackages() as $package) {
            $packageDependencies = $this->getComposerDependencies($package . '/composer.json');
            foreach ($packageDependencies as $dependency => $version) {
                // Skip web-auth/* dependencies
                if (str_starts_with((string) $dependency, 'web-token/')) {
                    continue;
                }

                $message = sprintf(
                    'Dependency "%s" from package "%s" is not defined in root composer.json',
                    $dependency,
                    $package
                );
                static::assertArrayHasKey($dependency, $rootDependencies, $message);

                $message = sprintf(
                    'Dependency "%s:%s" from package "%s" requires a different version in the root composer.json',
                    $dependency,
                    $version,
                    $package
                );
                static::assertSame($version, $rootDependencies[$dependency], $message);

                $usedDependencies[] = $dependency;
            }
        }

        $unusedDependencies = array_diff(array_keys($rootDependencies), array_unique($usedDependencies));
        $message = sprintf(
            'Dependencies declared in root composer.json, which are not declared in any sub-package: %s',
            implode(', ', $unusedDependencies)
        );
        static::assertCount(0, $unusedDependencies, $message);
    }

    #[Test]
    public function rootReplacesSubPackages(): void
    {
        $rootReplaces = $this->getComposerReplaces(__DIR__ . '/../composer.json');
        foreach ($this->listSubPackages() as $path) {
            $packageName = $this->getComposerPackageName($path . '/composer.json');
            $message = sprintf('Root composer.json must replace the sub-packages "%s"', $packageName);
            static::assertArrayHasKey($packageName, $rootReplaces, $message);
        }
    }

    private function listSubPackages(?string $path = self::SRC_DIR): Traversable
    {
        foreach (new DirectoryIterator($path) as $dirInfo) {
            if ($dirInfo->getFilename() === 'composer.json') {
                yield $dirInfo->getPath();
            } elseif ($dirInfo->isDir() && $dirInfo->isDot()) {
                continue;
            } elseif ($dirInfo->isDir()) {
                yield from $this->listSubPackages($dirInfo->getRealPath());
            }
        }
    }

    private function getComposerDependencies(string $composerFilePath): array
    {
        return $this->parseComposerFile($composerFilePath)['require'];
    }

    private function getComposerPackageName(string $composerFilePath): string
    {
        return $this->parseComposerFile($composerFilePath)['name'];
    }

    private function getComposerReplaces(string $composerFilePath): array
    {
        return $this->parseComposerFile($composerFilePath)['replace'];
    }

    private function parseComposerFile(string $composerFilePath): array
    {
        return json_decode(file_get_contents($composerFilePath), true, 512, JSON_THROW_ON_ERROR);
    }
}
