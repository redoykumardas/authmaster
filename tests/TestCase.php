<?php

namespace Redoy\AuthMaster\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Redoy\AuthMaster\AuthMasterServiceProvider;

abstract class TestCase extends OrchestraTestCase
{
    /**
     * Register package service providers.
     */
    protected function getPackageProviders($app)
    {
        return [AuthMasterServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Configure in-memory sqlite for tests before providers boot
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Avoid requiring external auth packages in tests; ensure package uses simple 'api' middleware
        $app['config']->set('authmaster.auth_middleware', 'api');
        // Use array cache driver for predictable in-memory cache behavior in tests
        $app['config']->set('cache.default', 'array');
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Load default Laravel migrations (creates users table)
        $this->loadLaravelMigrations();
    }
}
