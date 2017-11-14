<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Console;

use Jose\Component\Core\Converter\JsonConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\KeyAnalyzer\JWKAnalyzerManager;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Class KeysetAnalyzerCommand.
 */
final class KeysetAnalyzerCommand extends Command
{
    /**
     * @var JWKAnalyzerManager
     */
    private $analyzerManager;

    /**
     * @var JsonConverter
     */
    private $jsonConverter;

    /**
     * KeyAnalyzerCommand constructor.
     *
     * @param JWKAnalyzerManager $analyzerManager
     * @param JsonConverter      $jsonConverter
     * @param string|null        $name
     */
    public function __construct(JWKAnalyzerManager $analyzerManager, JsonConverter $jsonConverter, string $name = null)
    {
        parent::__construct($name);
        $this->analyzerManager = $analyzerManager;
        $this->jsonConverter = $jsonConverter;
    }

    /**
     * {@inheritdoc}
     */
    protected function configure()
    {
        parent::configure();
        $this
            ->setName('keyset:analyze')
            ->setDescription('JWKSet quality analyzer.')
            ->setHelp('This command will analyze a JWKSet object and find security issues.')
            ->addArgument('jwkset', InputArgument::REQUIRED, 'The JWKSet object')
        ;
    }

    /**
     * {@inheritdoc}
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $jwkset = $this->getKeyset($input);

        $privateKeys = 0;
        $publicKeys = 0;
        $sharedKeys = 0;
        $mixedKeys = false;

        foreach ($jwkset as $kid => $jwk) {
            $output->writeln(sprintf('Analysing key with index/kid "%s"', $kid));
            $messages = $this->analyzerManager->analyze($jwk);
            if (!empty($messages)) {
                foreach ($messages as $message) {
                    $output->writeln('    '.$message);
                }
            } else {
                $output->writeln('    No issue with this key');
            }

            switch (true) {
                case 'oct' === $jwk->get('kty'):
                    $sharedKeys++;
                    if (0 !== $privateKeys + $publicKeys) {
                        $mixedKeys = true;
                    }

                    break;
                case in_array($jwk->get('kty'), ['RSA', 'EC', 'OKP']):
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

    /**
     * @param InputInterface $input
     *
     * @return JWKSet
     */
    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        $json = $this->jsonConverter->decode($jwkset);
        if (is_array($json)) {
            return JWKSet::createFromKeyData($json);
        }

        throw new \InvalidArgumentException('The argument must be a valid JWKSet.');
    }
}
