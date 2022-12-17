<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use Jose\Component\KeyManagement\JWKFactory;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class NoneKeyGeneratorCommand extends GeneratorCommand
{
    protected static $defaultName = 'key:generate:none';

    protected static $defaultDescription = 'Generate a none key (JWK format). This key type is only supposed to be used with the "none" algorithm.';

    protected function configure(): void
    {
        parent::configure();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createNoneKey($args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }
}
