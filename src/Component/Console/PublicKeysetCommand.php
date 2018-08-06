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
use Jose\Component\Core\JWKSet;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class PublicKeysetCommand extends ObjectOutputCommand
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
            ->setName('keyset:convert:public')
            ->setDescription('Convert private keys in a key set into public keys. Symmetric keys (shared keys) are not changed.')
            ->setHelp('This command converts private keys in a key set into public keys.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwkset = $this->getKeyset($input);
        $newJwkset = JWKSet::createFromKeys([]);

        foreach ($jwkset->all() as $jwk) {
            $newJwkset = $newJwkset->with($jwk->toPublic());
        }
        $this->prepareJsonOutput($input, $output, $newJwkset);
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
}
