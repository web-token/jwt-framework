<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Override;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use function is_string;

#[AsCommand(name: 'key:generate:mldsa', description: 'Generate an ML-DSA key (JWK format, AKP key type)')]
final class MldsaKeyGeneratorCommand extends GeneratorCommand
{
    #[Override]
    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('algorithm', InputArgument::REQUIRED, 'Parameter set of the key: ML-DSA-44, ML-DSA-65 or ML-DSA-87. Needs PHP 8.4 and OpenSSL 3.5.');
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $algorithm = $input->getArgument('algorithm');
        if (! is_string($algorithm)) {
            throw new InvalidArgumentException('Invalid algorithm');
        }
        $args = $this->getOptions($input);

        $jwk = $this->jwkFactory->mldsa($algorithm, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }
}
