<?php

namespace Redoy\AuthMaster\Tests\Feature;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\AuthMasterServiceProvider;

class IsolationTest extends TestCase
{
    public function test_it_loads_the_package_service_provider()
    {
        $providers = $this->app->getLoadedProviders();

        $this->assertArrayHasKey(AuthMasterServiceProvider::class, $providers);
    }

    public function test_it_can_resolve_application_instance()
    {
        $this->assertNotNull($this->app);
        $this->assertInstanceOf(\Illuminate\Foundation\Application::class, $this->app);
    }
}
