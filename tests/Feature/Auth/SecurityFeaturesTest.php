<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Queue;
use Redoy\AuthMaster\Jobs\SendOtpJob;
use Redoy\AuthMaster\Models\DeviceSession;
use Redoy\AuthMaster\Services\EmailVerificationService;
use Redoy\AuthMaster\Services\TwoFactorService;
use Redoy\AuthMaster\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;

class SecurityFeaturesTest extends TestCase
{
    use RefreshDatabase;
    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__ . '/../../src/database/migrations'));

        if (!\Illuminate\Support\Facades\Schema::hasTable('users')) {
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
    }

    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);

        // Ensure OTP cooldown is set for testing
        $app['config']->set('authmaster.otp.resend_delay_seconds', 60);
        $app['config']->set('authmaster.otp.use_queue', true);
        $app['config']->set('authmaster.security.max_login_attempts_per_device', 3);
    }

    protected function createUser()
    {
        $userModel = config('auth.providers.users.model');
        $user = new $userModel();
        $user->name = 'Test User';
        $user->email = 'test@example.com';
        $user->password = bcrypt('password');
        $user->save();
        return $user;
    }

    /** @test */
    public function test_otp_resend_cooldown_is_enforced()
    {
        $user = $this->createUser();
        $service = app(EmailVerificationService::class);

        // First request should succeed
        $result1 = $service->sendOtp($user);
        $this->assertTrue($result1['success']);

        // Second immediate request should fail
        $result2 = $service->sendOtp($user);
        $this->assertFalse($result2['success']);
        $this->assertStringContainsString('Please wait', $result2['message']);
    }

    /** @test */
    public function test_otp_is_queued_when_configured()
    {
        Bus::fake();
        $user = $this->createUser();
        $service = app(EmailVerificationService::class);

        $service->sendOtp($user);

        Bus::assertDispatched(SendOtpJob::class);
    }

    /** @test */
    public function test_device_based_login_lockout()
    {
        $ip = '127.0.0.1';
        $deviceId = 'device_xyz';
        $email = 'locked@example.com';

        $security = app(\Redoy\AuthMaster\Contracts\SecurityServiceInterface::class);

        // Record failed attempts up to the limit
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($security->allowLoginAttempt($email, $ip, $deviceId));
            $security->recordFailedAttempt($email, $ip, $deviceId);
        }

        // Next attempt should be blocked
        $this->assertFalse($security->allowLoginAttempt($email, $ip, $deviceId));

        // But another device should NOT be blocked for the same email/IP (unless global limit hit)
        $this->assertTrue($security->allowLoginAttempt($email, $ip, 'different_device'));
    }

    /** @test */
    public function test_device_information_is_captured_in_session()
    {
        $user = $this->createUser();
        $deviceService = app(\Redoy\AuthMaster\Contracts\DeviceSessionServiceInterface::class);

        $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
        $request = Request::create('/test', 'POST', [], [], [], [
            'HTTP_USER_AGENT' => $userAgent,
            'REMOTE_ADDR' => '127.0.0.1'
        ]);

        $deviceService->createOrUpdateSession($user, 'Windows Desktop', $request, 'token_123', []);

        $session = DeviceSession::where('user_id', $user->id)->first();

        $this->assertEquals('Chrome', $session->browser);
        $this->assertEquals('Windows', $session->os);
        $this->assertEquals('desktop', $session->device_type);
    }

    /** @test */
    public function test_registration_rate_limiting_per_device()
    {
        $ip = '127.0.0.1';
        $deviceId = 'reg_device_1';
        $security = app(\Redoy\AuthMaster\Contracts\SecurityServiceInterface::class);

        // Limit is 3 in config for this test
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($security->allowRegistrationAttempt($ip, $deviceId));
            $security->recordRegistrationAttempt($ip, $deviceId);
        }

        // 4th attempt should be blocked
        $this->assertFalse($security->allowRegistrationAttempt($ip, $deviceId));

        // Another device should be fine
        $this->assertTrue($security->allowRegistrationAttempt($ip, 'reg_device_2'));
    }

    /** @test */
    public function test_device_info_auto_capture_from_headers()
    {
        $user = $this->createUser();
        $authManager = app(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);

        // Create a real request object
        $request = \Redoy\AuthMaster\Http\Requests\LoginRequest::create('/login', 'POST', [
            'email' => $user->email,
            'password' => 'password',
        ]);
        $request->headers->set('X-Device-Name', 'Postman App');
        $request->headers->set('User-Agent', 'PostmanRuntime/7.26.8');
        $request->server->set('REMOTE_ADDR', '1.2.3.4');

        // Mock validation for the FormRequest
        $request->setContainer(app())->setRedirector(app(\Illuminate\Routing\Redirector::class));
        $request->setValidator(app(\Illuminate\Validation\Factory::class)->make(
            $request->all(),
            $request->rules(),
            $request->messages()
        ));

        // Use LoginData to extract everything
        $loginData = \Redoy\AuthMaster\DTOs\LoginData::fromRequest($request);

        $authManager->finalizeLoginFromData(
            $user,
            $loginData->deviceId,
            $loginData->deviceName,
            $loginData->ipAddress,
            $loginData->userAgent
        );

        $session = DeviceSession::where('user_id', $user->id)->first();

        $this->assertEquals('Postman App', $session->device_name);
        $this->assertEquals('1.2.3.4', $session->ip_address);
        $this->assertEquals('PostmanRuntime/7.26.8', $session->user_agent);
    }
}
