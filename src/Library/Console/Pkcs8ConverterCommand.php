<?php

declare(strict_types=1);

namespace Jose\Component\Console;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\ECKey;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Core\Util\OKPKey;
use Jose\Component\Core\Util\RSAKey;
use Override;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use function is_array;
use function is_string;

#[AsCommand(name: 'key:convert:pkcs8', description: 'Converts a RSA, EC or OKP key into PKCS#8 key.')]
final class Pkcs8ConverterCommand extends ObjectOutputCommand
{
    #[Override]
    protected function configure(): void
    {
        parent::configure();
        $this
            ->setHelp(
                'This command converts a RSA, EC or OKP key into a PKCS#8 key. As PKCS#8 only covers private keys, public keys are converted into a SubjectPublicKeyInfo structure.'
            )
            ->addArgument('jwk', InputArgument::REQUIRED, 'The key');
    }

    #[Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $jwk = $input->getArgument('jwk');
        if (! is_string($jwk)) {
            throw new InvalidArgumentException('Invalid JWK');
        }
        $json = JsonConverter::decode($jwk);
        if (! is_array($json)) {
            throw new InvalidArgumentException('Invalid JWK.');
        }
        $key = new JWK($json);

        $pem = match ($key->get('kty')) {
            'RSA' => RSAKey::createFromJWK($key)->toPEM(),
            'EC' => ECKey::convertToPKCS8PEM($key),
            'OKP' => OKPKey::convertToPKCS8PEM($key),
            default => throw new InvalidArgumentException('Not a RSA, EC or OKP key.'),
        };
        $output->write($pem);

        return self::SUCCESS;
    }
}
