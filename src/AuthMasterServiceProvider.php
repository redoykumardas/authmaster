<?php

namespace Redoy\AuthMaster;

use Illuminate\Support\ServiceProvider;

class AuthMasterServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Merge package config
        $this->mergeConfigFrom(__DIR__ . '/config/authmaster.php', 'authmaster');

        // Bind core services
        $this->app->singleton(Services\AuthManager::class);
        $this->app->singleton(Services\TokenService::class);
        $this->app->singleton(Services\PasswordService::class);
        $this->app->singleton(Services\TwoFactorService::class);
        $this->app->singleton(Services\SocialLoginService::class);
        $this->app->singleton(Services\SecurityService::class);
        $this->app->singleton(Services\ValidationManager::class);
        $this->app->singleton(Services\DeviceSessionService::class);
    }

    public function boot()
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/config/authmaster.php' => config_path('authmaster.php'),
        ], 'config');

        // Load routes
        $this->loadRoutesFrom(__DIR__ . '/routes/api.php');

        // Load migrations if exists in package
        if (is_dir(__DIR__ . '/database/migrations')) {
            $this->loadMigrationsFrom(__DIR__ . '/database/migrations');
        }

        // Load and publish views (email templates)
        $this->loadViewsFrom(__DIR__ . '/resources/views', 'authmaster');
        $this->publishes([
            __DIR__ . '/resources/views' => resource_path('views/vendor/authmaster'),
        ], 'views');

        // Publish migrations
        $this->publishes([
            __DIR__ . '/database/migrations' => database_path('migrations'),
        ], 'migrations');

        // Register middleware alias
        if ($this->app->bound('router')) {
            $router = $this->app->make('router');
            if (method_exists($router, 'aliasMiddleware')) {
                $router->aliasMiddleware('authmaster.attach_device', Http\Middleware\AttachDeviceId::class);
            }
        }
    }
}
