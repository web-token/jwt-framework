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

namespace Jose;

use DirectoryIterator;
use PHPUnit\Framework\TestCase;
use Traversable;

/**
 * @internal
 * @note Courtesy of @scheb
 * @author Christian Scheb (https://github.com/scheb)
 * @see https://github.com/scheb/2fa/commit/94ff439212f465d8c9d146bf87d82ca32c4c4cbc#commitcomment-41153585
 */
class ComposerJsonTest extends TestCase
{
    private const SRC_DIR = __DIR__.'/../src';

    /**
     * @test
     */
    public function packageDependenciesEqualRootDependencies(): void
    {
        $usedDependencies = ['symfony/symfony']; // Some builds add this to composer.json
        $rootDependencies = $this->getComposerDependencies(__DIR__.'/../composer.json');

        foreach ($this->listSubPackages() as $package) {
            $packageDependencies = $this->getComposerDependencies($package.'/composer.json');
            foreach ($packageDependencies as $dependency => $version) {
                // Skip web-auth/* dependencies
                if (0 === mb_strpos($dependency, 'web-token/')) {
                    continue;
                }

                $message = sprintf('Dependency "%s" from package "%s" is not defined in root composer.json', $dependency, $package);
                static::assertArrayHasKey($dependency, $rootDependencies, $message);

                $message = sprintf('Dependency "%s:%s" from package "%s" requires a different version in the root composer.json', $dependency, $version, $package);
                static::assertEquals($version, $rootDependencies[$dependency], $message);

                $usedDependencies[] = $dependency;
            }
        }

        $unusedDependencies = array_diff(array_keys($rootDependencies), array_unique($usedDependencies));
        $message = sprintf('Dependencies declared in root composer.json, which are not declared in any sub-package: %s', implode($unusedDependencies));
        static::assertCount(0, $unusedDependencies, $message);
    }

    /**
     * @test
     */
    public function rootReplacesSubPackages(): void
    {
        $rootReplaces = $this->getComposerReplaces(__DIR__.'/../composer.json');
        foreach ($this->listSubPackages() as $path) {
            $packageName = $this->getComposerPackageName($path.'/composer.json');
            $message = sprintf('Root composer.json must replace the sub-packages "%s"', $packageName);
            static::assertArrayHasKey($packageName, $rootReplaces, $message);
        }
    }

    private function listSubPackages(?string $path = self::SRC_DIR): Traversable
    {
        $packageFolders = [
            'Bundle',
            'Component',
            'EncryptionAlgorithm',
            'ContentEncryption',
            'KeyEncryption',
            'SignatureAlgorithm'
        ];
        foreach (new DirectoryIterator($path) as $dirInfo) {
            if (in_array($dirInfo->getFilename(), $packageFolders, true)) {
                yield from $this->listSubPackages($dirInfo->getRealPath());
            } else  if ($dirInfo->isDir() && !$dirInfo->isDot() && $dirInfo->getFilename() !== '.github') {
                yield $dirInfo->getRealPath();
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
        return json_decode(file_get_contents($composerFilePath), true);
    }
}
