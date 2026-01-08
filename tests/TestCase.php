<?php

namespace Redoy\AuthMaster\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Redoy\AuthMaster\Providers\AuthMasterServiceProvider;

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
        $app['config']->set('app.key', 'base64:uK6D0+nC5XmY4e8k/D+uW/Kj5G6nU7uW4j5m6nU7uW4=');
        // Configure in-memory sqlite for tests before providers boot
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Avoid requiring external auth packages in tests; ensure package uses simple 'auth:web' or similar
        $app['config']->set('authmaster.auth_middleware', 'web');
        // Use array cache driver for predictable in-memory cache behavior in tests
        $app['config']->set('cache.default', 'array');

        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', [
            'driver' => 'session',
            'provider' => 'users',
        ]);
        $app['config']->set('auth.providers.users', [
            'driver' => 'eloquent',
        ]);
        if (class_exists(\App\Models\User::class)) {
            $app['config']->set('auth.providers.users.model', \App\Models\User::class);
        } else {
            $app['config']->set('auth.providers.users.model', \Illuminate\Foundation\Auth\User::class);
        }
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
        $this->loadMigrationsFrom(__DIR__ . '/../src/Database/Migrations');

        // Load Sanctum migrations
        $sanctumMigrations = __DIR__ . '/../../../../vendor/laravel/sanctum/database/migrations';
        if (is_dir($sanctumMigrations)) {
            $this->loadMigrationsFrom($sanctumMigrations);
        }
    }

    protected function setUp(): void
    {
        parent::setUp();
    }
}
