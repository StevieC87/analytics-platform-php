<?php
// The Symfony bundle against the real DependencyInjection component: what it
// registers, its options, and that a service you defined yourself in
// services.yaml (the setup before the bundle) is kept instead of its own.
// Needs Symfony, which this package doesn't depend on: point it at a Symfony
// app's autoloader, otherwise it is skipped.
//
//   SYMFONY_AUTOLOAD=/path/to/app/vendor/autoload.php php test/SymfonyBundleTest.php

$autoload = getenv('SYMFONY_AUTOLOAD');
if (!$autoload || !is_file($autoload)) {
    echo "SKIPPED: set SYMFONY_AUTOLOAD to a Symfony app's vendor/autoload.php\n";
    exit(0);
}
require $autoload;
spl_autoload_register(function ($class) {
    if (strncmp($class, 'AnalyticsPlatform\\', 18) === 0) {
        $file = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, 18)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
}, true, true);

use AnalyticsPlatform\Platform;
use AnalyticsPlatform\Symfony\AnalyticsPlatformBundle;
use AnalyticsPlatform\Symfony\CacheCounter;
use AnalyticsPlatform\Symfony\PlatformSubscriber;
use AnalyticsPlatform\Symfony\QueryMiddleware;
use Symfony\Component\DependencyInjection\Compiler\MergeExtensionConfigurationPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

$failed = 0;
$checked = 0;
function check($name, $ok)
{
    global $failed, $checked;
    $checked++;
    if (!$ok) {
        $failed++;
        fwrite(STDERR, "FAIL: $name\n");
    }
}

// What the kernel does with a bundle's extension: loaded into the container
// under its alias, then merged with what the app defined itself.
function container(array $configs, array $own = array())
{
    $builder = new ContainerBuilder();
    $builder->setParameter('kernel.project_dir', '/app');
    $builder->setParameter('kernel.environment', 'test');
    $builder->setParameter('kernel.debug', false);
    $builder->setParameter('kernel.build_dir', sys_get_temp_dir());
    $bundle = new AnalyticsPlatformBundle();
    $extension = $bundle->getContainerExtension();
    $builder->registerExtension($extension);
    foreach ($configs as $config) {
        $builder->loadFromExtension($extension->getAlias(), $config);
    }
    foreach ($own as $id => $definition) {
        $builder->setDefinition($id, $definition);
    }
    (new MergeExtensionConfigurationPass())->process($builder);
    return array($builder, $extension->getAlias());
}

list($builder, $alias) = container(array(array()));
check('the config key is analytics_platform', $alias === 'analytics_platform');
check('the Platform is registered', $builder->hasDefinition(Platform::class));
check('the subscriber, autoconfigured', $builder->hasDefinition(PlatformSubscriber::class) && $builder->getDefinition(PlatformSubscriber::class)->isAutoconfigured());
check('the counter', $builder->hasDefinition(CacheCounter::class));
$options = $builder->getDefinition(Platform::class)->getArgument(0);
check('platform: symfony', $options['platform'] === 'symfony');
check('storage under var/', $options['storage'] === '%kernel.project_dir%/var/analytics-platform');
check('the keys from the environment, empty when unset', strpos($options['site_id'], '%env(default::ANALYTICS_SITE_ID)%') !== false || strpos($options['site_id'], 'env_') !== false);
check('no protect_only unless asked', !isset($options['protect_only']));
check('QueryMiddleware only with Doctrine', $builder->hasDefinition(QueryMiddleware::class) === interface_exists('Doctrine\DBAL\Driver\Middleware'));

list($builder) = container(array(array('protect_only' => array('/admin', 'checkout_*'), 'options' => array('server_name' => 'web', 'posture' => true))));
$options = $builder->getDefinition(Platform::class)->getArgument(0);
check('protect_only reaches the Platform', $options['protect_only'] === array('/admin', 'checkout_*'));
check('options go over the bundle\'s', $options['server_name'] === 'web' && $options['posture'] === true && $options['platform'] === 'symfony');

$mine = new Definition(Platform::class, array(array('platform' => 'symfony', 'site_id' => 'mine')));
list($builder) = container(array(array()), array(Platform::class => $mine));
check('a Platform defined in services.yaml is kept', $builder->getDefinition(Platform::class)->getArgument(0)['site_id'] === 'mine');

echo ($failed ? "FAILED" : "OK") . ": $checked checks, $failed failed\n";
exit($failed ? 1 : 0);
