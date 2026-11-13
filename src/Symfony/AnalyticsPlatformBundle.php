<?php
// Symfony in one line: in config/bundles.php,
//
//   AnalyticsPlatform\Symfony\AnalyticsPlatformBundle::class => ['all' => true],
//
// and the keys in .env.local (ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET,
// ANALYTICS_ENDPOINT). It registers what the README's services.yaml block
// does: the Platform, its rate limit counter (CacheCounter) and the
// subscriber; HttpClientBreadcrumbs when symfony/http-client is installed;
// and QueryMiddleware, on every Doctrine connection, when DBAL is. Until the
// keys are set, the site runs as before.
//
// Options, all optional, in config/packages/analytics_platform.yaml:
//
//   analytics_platform:
//       protect_only: ['/admin', 'checkout_*']
//       options: { server_name: web, firewall: { mode: monitor }, posture: true }
//
// 'options' are the plain PHP package's, over the ones set here. A service
// you define yourself in services.yaml (the setup before this bundle) is
// kept, and this bundle's one of the same name is dropped, so the two can't
// register anything twice.

namespace AnalyticsPlatform\Symfony;

use AnalyticsPlatform\Platform;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class AnalyticsPlatformBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->arrayNode('protect_only')->scalarPrototype()->end()->end()
                ->variableNode('options')->defaultValue(array())->end()
            ->end();
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $options = array(
            'site_id' => '%env(default::ANALYTICS_SITE_ID)%',
            'secret' => '%env(default::ANALYTICS_SITE_SECRET)%',
            // Empty when unset: the Platform then reads ANALYTICS_FIREWALL_ENDPOINT,
            // the name the services.yaml setup used.
            'endpoint' => '%env(default::ANALYTICS_ENDPOINT)%',
            'server_name' => '%env(default::ANALYTICS_SERVER_NAME)%',
            'platform' => 'symfony',
            'storage' => '%kernel.project_dir%/var/analytics-platform',
            'inventory' => array('root' => '%kernel.project_dir%'),
            'counter' => new Reference(CacheCounter::class),
        );
        if (!empty($config['protect_only'])) {
            $options['protect_only'] = array_values($config['protect_only']);
        }
        if (is_array($config['options'])) {
            $options = $config['options'] + $options;
        }

        $builder->register(Platform::class, Platform::class)->setArguments(array($options));
        $builder->register(CacheCounter::class, CacheCounter::class)->setAutowired(true);
        $builder->register(PlatformSubscriber::class, PlatformSubscriber::class)->setAutowired(true)->setAutoconfigured(true);
        if (class_exists(\Symfony\Component\HttpClient\HttpClient::class)) {
            $builder->register(HttpClientBreadcrumbs::class, HttpClientBreadcrumbs::class)->setAutowired(true)->setAutoconfigured(true);
        }
        if (interface_exists(\Doctrine\DBAL\Driver\Middleware::class)) {
            $builder->register(QueryMiddleware::class, QueryMiddleware::class)->setAutowired(true)->addTag('doctrine.middleware');
        }
    }
}
