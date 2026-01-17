<?php

namespace Redoy\AuthMaster\Providers;

use Illuminate\Support\ServiceProvider;
use Redoy\AuthMaster\Contracts;
use Redoy\AuthMaster\Services;
use Redoy\AuthMaster\Console;
use Redoy\AuthMaster\Http;
use Redoy\AuthMaster\DTOs\RegisterData;
use Redoy\AuthMaster\Http\Requests\RegisterRequest;

class AuthMasterServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/authmaster.php', 'authmaster');

        $this->registerContracts();

        // Register Specialized Providers
        $this->app->register(EventServiceProvider::class);
        $this->app->register(RouteServiceProvider::class);
    }

    /**
     * Register interface bindings for dependency injection.
     */
    protected function registerContracts(): void
    {
        $this->app->singleton(Contracts\OtpGeneratorInterface::class, Services\OtpGenerator::class);
        $this->app->singleton(Contracts\TokenServiceInterface::class, Services\TokenService::class);
        $this->app->singleton(Contracts\DeviceSessionServiceInterface::class, Services\DeviceSessionService::class);
        $this->app->singleton(Contracts\PasswordServiceInterface::class, Services\PasswordService::class);
        $this->app->singleton(Contracts\SecurityServiceInterface::class, Services\SecurityService::class);
        $this->app->singleton(Contracts\ValidationManagerInterface::class, Services\ValidationManager::class);
        $this->app->singleton(Contracts\TwoFactorServiceInterface::class, Services\TwoFactorService::class);
        $this->app->singleton(Contracts\SocialLoginServiceInterface::class, Services\SocialLoginService::class);
        $this->app->singleton(Contracts\AuthManagerInterface::class, Services\AuthManager::class);

        // Bind request-scoped services
        $this->app->bind(Contracts\EmailVerificationServiceInterface::class, Services\EmailVerificationService::class);
        $this->app->bind(Contracts\RegistrationServiceInterface::class, Services\RegistrationService::class);

        // Bind RegisterData to resolve from the current request
        $this->app->bind(RegisterData::class, function ($app) {
            try {
                return RegisterData::fromRequest($app->make(RegisterRequest::class));
            } catch (\Illuminate\Validation\ValidationException $e) {
                return null;
            }
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->bootForConsole();
        }

        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'authmaster');

        // Register middleware aliases
        if ($this->app->bound('router')) {
            $router = $this->app->make('router');
            if (method_exists($router, 'aliasMiddleware')) {
                $router->aliasMiddleware('authmaster.attach_device', Http\Middleware\AttachDeviceId::class);
                $router->aliasMiddleware('authmaster.verified', Http\Middleware\EnsureEmailIsVerified::class);
                $router->aliasMiddleware('authmaster.track_device', Http\Middleware\TrackDeviceActivity::class);
            }
        }
    }

    protected function bootForConsole(): void
    {
        $this->publishes([
            __DIR__ . '/../config/authmaster.php' => config_path('authmaster.php'),
        ], 'config');

        if (is_dir(__DIR__ . '/../Database/Migrations')) {
            $this->loadMigrationsFrom(__DIR__ . '/../Database/Migrations');
        }

        $this->publishes([
            __DIR__ . '/../resources/views' => resource_path('views/vendor/authmaster'),
        ], 'views');

        $this->publishes([
            __DIR__ . '/../Database/Migrations' => database_path('migrations'),
        ], 'migrations');

        $this->commands([
            Console\Commands\ClearInactiveSessions::class,
            Console\Commands\ManageUser::class,
        ]);
    }
}