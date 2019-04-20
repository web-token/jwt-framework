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

use InvalidArgumentException;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class KeysetAnalyzerCommand extends Command
{
    /**
     * @var KeyAnalyzerManager
     */
    private $analyzerManager;

    public function __construct(KeyAnalyzerManager $analyzerManager, string $name = null)
    {
        parent::__construct($name);
        $this->analyzerManager = $analyzerManager;
    }

    protected function configure(): void
    {
        parent::configure();
        $this
            ->setName('keyset:analyze')
            ->setDescription('JWKSet quality analyzer.')
            ->setHelp('This command will analyze a JWKSet object and find security issues.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $output->getFormatter()->setStyle('success', new OutputFormatterStyle('white', 'green'));
        $output->getFormatter()->setStyle('high', new OutputFormatterStyle('white', 'red', ['bold']));
        $output->getFormatter()->setStyle('medium', new OutputFormatterStyle('yellow'));
        $output->getFormatter()->setStyle('low', new OutputFormatterStyle('blue'));

        $jwkset = $this->getKeyset($input);

        $privateKeys = 0;
        $publicKeys = 0;
        $sharedKeys = 0;
        $mixedKeys = false;

        foreach ($jwkset as $kid => $jwk) {
            $output->writeln(sprintf('Analysing key with index/kid "%s"', $kid));
            $messages = $this->analyzerManager->analyze($jwk);
            if (0 === $messages->count()) {
                $output->writeln('    <success>All good! No issue found.</success>');
            } else {
                foreach ($messages->all() as $message) {
                    $output->writeln('    <'.$message->getSeverity().'>* '.$message->getMessage().'</'.$message->getSeverity().'>');
                }
            }

            switch (true) {
                case 'oct' === $jwk->get('kty'):
                    $sharedKeys++;
                    if (0 !== $privateKeys + $publicKeys) {
                        $mixedKeys = true;
                    }

                    break;
                case \in_array($jwk->get('kty'), ['RSA', 'EC', 'OKP'], true):
                    if ($jwk->has('d')) {
                        ++$privateKeys;
                        if (0 !== $sharedKeys + $publicKeys) {
                            $mixedKeys = true;
                        }
                    } else {
                        ++$publicKeys;
                        if (0 !== $privateKeys + $sharedKeys) {
                            $mixedKeys = true;
                        }
                    }

                    break;
                default:
                    break;
            }
        }

        if ($mixedKeys) {
            $output->writeln('/!\\ This key set mixes share, public and private keys. You should create one key set per key type. /!\\');
        }
    }

    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        if (!\is_string($jwkset)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }
        $json = JsonConverter::decode($jwkset);
        if (!\is_array($json)) {
            throw new InvalidArgumentException('The argument must be a valid JWKSet.');
        }

        return JWKSet::createFromKeyData($json);
    }
}
