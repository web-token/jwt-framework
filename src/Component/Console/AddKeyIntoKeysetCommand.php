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

namespace Jose\Component\Console;

use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class AddKeyIntoKeysetCommand extends ObjectOutputCommand
{
    /**
     * KeyAnalyzerCommand constructor.
     */
    public function __construct(JsonConverter $jsonConverter, string $name = null)
    {
        parent::__construct($jsonConverter, $name);
    }

    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:add:key')
            ->setDescription('Add a key into a key set.')
            ->setHelp('This command adds a key at the end of a key set.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
            ->addArgument('jwk', InputArgument::REQUIRED, 'The new JWK object');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwkset = $this->getKeyset($input);
        $jwk = $this->getKey($input);
        $jwkset = $jwkset->with($jwk);
        $this->prepareJsonOutput($input, $output, $jwkset);
    }

    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        $json = $this->jsonConverter->decode($jwkset);
        if (\is_array($json)) {
            return JWKSet::createFromKeyData($json);
        }

        throw new \InvalidArgumentException('The argument must be a valid JWKSet.');
    }

    private function getKey(InputInterface $input): JWK
    {
        $jwkset = $input->getArgument('jwk');
        $json = $this->jsonConverter->decode($jwkset);
        if (\is_array($json)) {
            return JWK::create($json);
        }

        throw new \InvalidArgumentException('The argument must be a valid JWK.');
    }
}
