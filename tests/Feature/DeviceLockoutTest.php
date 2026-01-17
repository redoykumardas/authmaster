<?php

namespace Redoy\AuthMaster\Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Redoy\AuthMaster\Contracts\SecurityServiceInterface;
use Redoy\AuthMaster\Exceptions\TooManyAttemptsException;
use Redoy\AuthMaster\Tests\TestCase;

class DeviceLockoutTest extends TestCase
{
    use RefreshDatabase;

    protected SecurityServiceInterface $securityService;

    protected function setUp(): void
    {
        parent::setUp();
        $this->securityService = app(SecurityServiceInterface::class);
        
        // Ensure config is set
        config(['authmaster.security.max_login_attempts_per_device' => 3]);
        config(['authmaster.security.device_lockout_duration_minutes' => 60]);
    }

    public function test_device_specific_lockout_is_enforced()
    {
        $deviceId = 'test-device-123';
        $ip = '127.0.0.1';

        // 3 failed attempts from different emails on the same device
        $this->securityService->recordFailedAttempt('user1@example.com', $ip, $deviceId);
        $this->securityService->recordFailedAttempt('user2@example.com', $ip, $deviceId);
        $this->securityService->recordFailedAttempt('user3@example.com', $ip, $deviceId);

        // 4th attempt should be blocked due to device lockout
        $this->expectException(TooManyAttemptsException::class);
        $this->expectExceptionMessage('Too many login attempts from this device');

        $this->securityService->allowLoginAttempt('user4@example.com', $ip, $deviceId);
    }

    public function test_device_lockout_does_not_affect_other_devices()
    {
        $deviceId1 = 'device-1';
        $deviceId2 = 'device-2';
        $ip = '127.0.0.1';

        // Lock out device 1
        for ($i = 0; $i < 3; $i++) {
            $this->securityService->recordFailedAttempt("user{$i}@example.com", $ip, $deviceId1);
        }

        // Device 1 should be locked out
        $lockoutCaught = false;
        try {
            $this->securityService->allowLoginAttempt('user-any@example.com', $ip, $deviceId1);
        } catch (TooManyAttemptsException $e) {
            $lockoutCaught = true;
            $this->assertStringContainsString('from this device', $e->getMessage());
        }
        $this->assertTrue($lockoutCaught, 'Device 1 should be locked out');

        // Device 2 should still be allowed
        $this->securityService->allowLoginAttempt('user-any@example.com', $ip, $deviceId2);
    }
}
