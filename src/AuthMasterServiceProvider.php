<?php

namespace Redoy\AuthMaster;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Redoy\AuthMaster\Contracts;
use Redoy\AuthMaster\Services;
use Redoy\AuthMaster\Events;
use Redoy\AuthMaster\Listeners;

class AuthMasterServiceProvider extends ServiceProvider
{
    /**
     * The event listener mappings for the package.
     *
     * @var array
     */
    protected $listen = [
        Events\LoginSuccessful::class => [
            Listeners\LogSecurityActivity::class,
        ],
        Events\LogoutSuccessful::class => [
            Listeners\LogSecurityActivity::class,
        ],
        Events\FailedLoginAttempt::class => [
            Listeners\LogSecurityActivity::class,
        ],
        Events\SuspiciousActivityDetected::class => [
            Listeners\LogSecurityActivity::class,
            Listeners\NotifySuspiciousActivity::class,
        ],
    ];

    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/config/authmaster.php', 'authmaster');

        $this->registerContracts();
    }

    /**
     * Register interface bindings for dependency injection.
     */
    protected function registerContracts(): void
    {
        // OTP Generator (no dependencies)
        $this->app->singleton(
            Contracts\OtpGeneratorInterface::class,
            Services\OtpGenerator::class
        );

        // Token Service (no dependencies)
        $this->app->singleton(
            Contracts\TokenServiceInterface::class,
            Services\TokenService::class
        );

        // Device Session Service (no dependencies)
        $this->app->singleton(
            Contracts\DeviceSessionServiceInterface::class,
            Services\DeviceSessionService::class
        );

        // Password Service (no dependencies)
        $this->app->singleton(
            Contracts\PasswordServiceInterface::class,
            Services\PasswordService::class
        );

        // Security Service (no dependencies)
        $this->app->singleton(
            Contracts\SecurityServiceInterface::class,
            Services\SecurityService::class
        );

        // Validation Manager (no dependencies)
        $this->app->singleton(
            Contracts\ValidationManagerInterface::class,
            Services\ValidationManager::class
        );

        // Two Factor Service (depends on OtpGenerator)
        $this->app->singleton(
            Contracts\TwoFactorServiceInterface::class,
            Services\TwoFactorService::class
        );

        // Email Verification Service (depends on OtpGenerator)
        $this->app->singleton(
            Contracts\EmailVerificationServiceInterface::class,
            Services\EmailVerificationService::class
        );

        // Social Login Service (depends on TokenService, DeviceSessionService)
        $this->app->singleton(
            Contracts\SocialLoginServiceInterface::class,
            Services\SocialLoginService::class
        );

        // Auth Manager (depends on multiple services)
        $this->app->singleton(
            Contracts\AuthManagerInterface::class,
            Services\AuthManager::class
        );

        // Registration Service (depends on AuthManager, EmailVerificationService)
        $this->app->singleton(
            Contracts\RegistrationServiceInterface::class,
            Services\RegistrationService::class
        );
    }

    public function boot()
    {
        // Publish config
        $this->publishes([
            __DIR__ . '/config/authmaster.php' => config_path('authmaster.php'),
        ], 'config');

        // Load routes with proper prefix and middleware
        Route::prefix('api')
            ->middleware('api')
            ->group(function () {
                $this->loadRoutesFrom(__DIR__ . '/routes/api.php');
            });

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

        // Register event listeners
        foreach ($this->listen as $event => $listeners) {
            foreach ($listeners as $listener) {
                Event::listen($event, $listener);
            }
        }

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                Console\Commands\ClearInactiveSessions::class,
                Console\Commands\ManageUser::class,
            ]);
        }

        // Register middleware aliases
        if ($this->app->bound('router')) {
            $router = $this->app->make('router');
            if (method_exists($router, 'aliasMiddleware')) {
                $router->aliasMiddleware('authmaster.attach_device', Http\Middleware\AttachDeviceId::class);
                $router->aliasMiddleware('authmaster.verified', Http\Middleware\EnsureEmailIsVerified::class);
            }
        }
    }
}