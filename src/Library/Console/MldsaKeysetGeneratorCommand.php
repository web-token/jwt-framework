<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use Jose\Component\Core\Exception\InvalidArgumentException;
use Jose\Component\Core\JWKSet;
use Override;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use function is_numeric;
use function is_string;

#[AsCommand(
    name: 'keyset:generate:mldsa',
    description: 'Generate a key set with ML-DSA keys (JWKSet format)'
)]
final class MldsaKeysetGeneratorCommand extends GeneratorCommand
{
    #[Override]
    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('quantity', InputArgument::REQUIRED, 'Quantity of keys in the key set.')
            ->addArgument('algorithm', InputArgument::REQUIRED, 'Parameter set of the keys: ML-DSA-44, ML-DSA-65 or ML-DSA-87. Needs PHP 8.4 and OpenSSL 3.5.');
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $quantity = $input->getArgument('quantity');
        $algorithm = $input->getArgument('algorithm');
        if (! is_numeric($quantity) || (int) $quantity < 1) {
            throw new InvalidArgumentException('Invalid quantity');
        }
        $quantity = (int) $quantity;
        if (! is_string($algorithm)) {
            throw new InvalidArgumentException('Invalid algorithm');
        }

        $keyset = new JWKSet([]);
        for ($i = 0; $i < $quantity; ++$i) {
            $args = $this->getOptions($input);
            $keyset = $keyset->with($this->jwkFactory->mldsa($algorithm, $args));
        }
        $this->prepareJsonOutput($input, $output, $keyset);

        return self::SUCCESS;
    }
}
