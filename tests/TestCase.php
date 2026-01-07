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

        $app['config']->set('auth.providers.users.model', \Illuminate\Foundation\Auth\User::class);
    }

    protected function defineDatabaseMigrations()
    {
        try {
            $this->loadLaravelMigrations();
        } catch (\Throwable $e) {
            // Fallback: manually create users table for tests
            \Illuminate\Support\Facades\Schema::create('users', function ($table) {
                $table->id();
                $table->string('name');
                $table->string('email')->unique();
                $table->string('password');
                $table->timestamp('email_verified_at')->nullable();
                $table->rememberToken();
                $table->timestamps();
            });
        }
        $this->loadMigrationsFrom(__DIR__ . '/../src/database/migrations');
    }

    protected function setUp(): void
    {
        parent::setUp();
    }
}
