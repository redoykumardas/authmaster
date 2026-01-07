<?php

namespace Redoy\AuthMaster\Tests\Unit;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\AuthMasterServiceProvider;

class ProviderTest extends TestCase
{
    public function test_service_provider_is_loaded()
    {
        $provider = $this->app->getProvider(AuthMasterServiceProvider::class);
        $this->assertNotNull($provider);
    }

    public function test_helpers_are_available()
    {
        $this->assertTrue(function_exists('authmaster_device_id'));
        $this->assertTrue(function_exists('authmaster_token_response'));
    }
}
