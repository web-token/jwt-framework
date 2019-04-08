<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console;

use Assert\Assertion;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class RotateKeysetCommand extends ObjectOutputCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:rotate')
            ->setDescription('Rotate a key set.')
            ->setHelp('This command removes the last key in a key set a place a new one at the beginning.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The new JWK object');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwkset = $this->getKeyset($input)->all();
        $jwk = $this->getKey($input);

        if (0 !== \count($jwkset)) {
            \array_pop($jwkset);
        }
        \array_unshift($jwkset, $jwk);

        $this->prepareJsonOutput($input, $output, JWKSet::createFromKeys($jwkset));
    }

    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        Assertion::string($jwkset, 'Invalid JWKSet');
        $json = JsonConverter::decode($jwkset);
        Assertion::isArray($json, 'The argument must be a valid JWKSet.');

        return JWKSet::createFromKeyData($json);
    }

    private function getKey(InputInterface $input): JWK
    {
        $jwk = $input->getArgument('jwk');
        Assertion::string($jwk, 'Invalid JWK');
        $json = JsonConverter::decode($jwk);
        Assertion::isArray($json, 'The argument must be a valid JWK.');

        return JWK::create($json);
    }
}
