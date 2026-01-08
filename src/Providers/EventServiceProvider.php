<?php

namespace Redoy\AuthMaster\Providers;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Redoy\AuthMaster\Events;
use Redoy\AuthMaster\Listeners;

class EventServiceProvider extends ServiceProvider
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

    public function boot(): void
    {
        foreach ($this->listen as $event => $listeners) {
            foreach ($listeners as $listener) {
                Event::listen($event, $listener);
            }
        }
    }
}
