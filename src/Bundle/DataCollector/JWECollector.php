<?php

declare(strict_types=1);

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Bundle\JoseFramework\Event\JWEBuiltFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEBuiltSuccessEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionFailureEvent;
use Jose\Bundle\JoseFramework\Event\JWEDecryptionSuccessEvent;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\JWESerializerManagerFactory;
use Override;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\VarDumper\Cloner\Data;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Throwable;

final class JWECollector implements Collector, EventSubscriberInterface
{
    /**
     * @var array<Data>
     */
    private array $jweDecryptionSuccesses = [];

    /**
     * @var array<Data>
     */
    private array $jweDecryptionFailures = [];

    /**
     * @var array<Data>
     */
    private array $jweBuiltSuccesses = [];

    /**
     * @var array<Data>
     */
    private array $jweBuiltFailures = [];

    /**
     * @var array<JWEBuilder>
     */
    private array $jweBuilders = [];

    /**
     * @var array<JWEDecrypter>
     */
    private array $jweDecrypters = [];

    /**
     * @var array<JWELoader>
     */
    private array $jweLoaders = [];

    public function __construct(
        private readonly ?JWESerializerManagerFactory $jweSerializerManagerFactory = null
    ) {
    }

    /**
     * @param array<string, mixed> $data
     */
    #[Override]
    public function collect(array &$data, Request $request, Response $response, ?Throwable $exception = null): void
    {
        $this->collectSupportedJWESerializations($data);
        $this->collectSupportedJWEBuilders($data);
        $this->collectSupportedJWEDecrypters($data);
        $this->collectSupportedJWELoaders($data);
        $this->collectEvents($data);
    }

    public function addJWEBuilder(string $id, JWEBuilder $jweBuilder): void
    {
        $this->jweBuilders[$id] = $jweBuilder;
    }

    public function addJWEDecrypter(string $id, JWEDecrypter $jweDecrypter): void
    {
        $this->jweDecrypters[$id] = $jweDecrypter;
    }

    public function addJWELoader(string $id, JWELoader $jweLoader): void
    {
        $this->jweLoaders[$id] = $jweLoader;
    }

    #[Override]
    public static function getSubscribedEvents(): array
    {
        return [
            JWEDecryptionSuccessEvent::class => ['catchJweDecryptionSuccess'],
            JWEDecryptionFailureEvent::class => ['catchJweDecryptionFailure'],
            JWEBuiltSuccessEvent::class => ['catchJweBuiltSuccess'],
            JWEBuiltFailureEvent::class => ['catchJweBuiltFailure'],
        ];
    }

    public function catchJweDecryptionSuccess(JWEDecryptionSuccessEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jweDecryptionSuccesses[] = $cloner->cloneVar($event);
    }

    public function catchJweDecryptionFailure(JWEDecryptionFailureEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jweDecryptionFailures[] = $cloner->cloneVar($event);
    }

    public function catchJweBuiltSuccess(JWEBuiltSuccessEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jweBuiltSuccesses[] = $cloner->cloneVar($event);
    }

    public function catchJweBuiltFailure(JWEBuiltFailureEvent $event): void
    {
        $cloner = new VarCloner();
        $this->jweBuiltFailures[] = $cloner->cloneVar($event);
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectSupportedJWESerializations(array &$data): void
    {
        $data['jwe']['jwe_serialization'] = [];
        if ($this->jweSerializerManagerFactory === null) {
            return;
        }
        $serializers = $this->jweSerializerManagerFactory->all();
        foreach ($serializers as $serializer) {
            $data['jwe']['jwe_serialization'][$serializer->name()] = $serializer->displayName();
        }
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectSupportedJWEBuilders(array &$data): void
    {
        $data['jwe']['jwe_builders'] = [];
        foreach ($this->jweBuilders as $id => $jweBuilder) {
            $data['jwe']['jwe_builders'][$id] = [
                'encryption_algorithms' => $jweBuilder->getKeyEncryptionAlgorithmManager()
                    ->list(),
            ];
        }
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectSupportedJWEDecrypters(array &$data): void
    {
        $data['jwe']['jwe_decrypters'] = [];
        foreach ($this->jweDecrypters as $id => $jweDecrypter) {
            $data['jwe']['jwe_decrypters'][$id] = [
                'encryption_algorithms' => $jweDecrypter->getKeyEncryptionAlgorithmManager()
                    ->list(),
            ];
        }
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectSupportedJWELoaders(array &$data): void
    {
        $data['jwe']['jwe_loaders'] = [];
        foreach ($this->jweLoaders as $id => $jweLoader) {
            $data['jwe']['jwe_loaders'][$id] = [
                'serializers' => $jweLoader->getSerializerManager()
                    ->names(),
                'encryption_algorithms' => $jweLoader->getJweDecrypter()
                    ->getKeyEncryptionAlgorithmManager()
                    ->list(),
            ];
        }
    }

    /**
     * @param array<string, array<string, mixed>> $data
     */
    private function collectEvents(array &$data): void
    {
        $data['jwe']['events'] = [
            'decryption_success' => $this->jweDecryptionSuccesses,
            'decryption_failure' => $this->jweDecryptionFailures,
            'built_success' => $this->jweBuiltSuccesses,
            'built_failure' => $this->jweBuiltFailures,
        ];
    }
}
