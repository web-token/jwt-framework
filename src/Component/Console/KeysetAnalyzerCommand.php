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

namespace Jose\Component\Console;

use InvalidArgumentException;
use function is_array;
use function is_string;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeysetAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\MessageBag;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatterStyle;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class KeysetAnalyzerCommand extends Command
{
    /**
     * @var KeysetAnalyzerManager
     */
    private $keysetAnalyzerManager;

    /**
     * @var KeyAnalyzerManager
     */
    private $keyAnalyzerManager;

    public function __construct(KeysetAnalyzerManager $keysetAnalyzerManager, KeyAnalyzerManager $keyAnalyzerManager, string $name = null)
    {
        parent::__construct($name);
        $this->keysetAnalyzerManager = $keysetAnalyzerManager;
        $this->keyAnalyzerManager = $keyAnalyzerManager;
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

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->getFormatter()->setStyle('success', new OutputFormatterStyle('white', 'green'));
        $output->getFormatter()->setStyle('high', new OutputFormatterStyle('white', 'red', ['bold']));
        $output->getFormatter()->setStyle('medium', new OutputFormatterStyle('yellow'));
        $output->getFormatter()->setStyle('low', new OutputFormatterStyle('blue'));

        $jwkset = $this->getKeyset($input);

        $messages = $this->keysetAnalyzerManager->analyze($jwkset);
        $this->showMessages($messages, $output);
        foreach ($jwkset as $kid => $jwk) {
            $output->writeln(sprintf('Analysing key with index/kid "%s"', $kid));
            $messages = $this->keyAnalyzerManager->analyze($jwk);
            $this->showMessages($messages, $output);
        }

        return 0;
    }

    private function showMessages(MessageBag $messages, OutputInterface $output): void
    {
        if (0 === $messages->count()) {
            $output->writeln('    <success>All good! No issue found.</success>');
        } else {
            foreach ($messages->all() as $message) {
                $output->writeln('    <'.$message->getSeverity().'>* '.$message->getMessage().'</'.$message->getSeverity().'>');
            }
        }
    }

    /**
     * @throws InvalidArgumentException if the JWKSet is invalid
     */
    private function getKeyset(InputInterface $input): JWKSet
    {
        $jwkset = $input->getArgument('jwkset');
        if (!is_string($jwkset)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }
        $json = JsonConverter::decode($jwkset);
        if (!is_array($json)) {
            throw new InvalidArgumentException('Invalid JWKSet');
        }

        return JWKSet::createFromKeyData($json);
    }
}
