<?php

namespace Redoy\AuthMaster\Tests\Unit;

use Redoy\AuthMaster\Contracts\TwoFactorServiceInterface;
use Redoy\AuthMaster\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;

class TwoFactorServiceTest extends TestCase
{
    public function test_generate_and_send_stores_code_and_sends_mail()
    {
        Mail::fake();

        $svc = $this->app->make(TwoFactorServiceInterface::class);
        $user = new \stdClass();
        $user->id = 10;
        $user->email = 'user@example.com';

        $svc->generateAndSend($user, 'device-x');

        // Verify code was cached
        $key = "authmaster_otp:{$user->id}:device-x";
        $this->assertNotNull(Cache::get($key));

        Mail::assertSent(\Redoy\AuthMaster\Mail\SendOtpMail::class);
    }

    public function test_verify_fails_when_expired()
    {
        $svc = $this->app->make(TwoFactorServiceInterface::class);
        $user = new \stdClass();
        $user->id = 11;

        $this->expectException(\Redoy\AuthMaster\Exceptions\AuthException::class);
        $this->expectExceptionMessage('Code expired');
        $svc->verify($user, '000000');
    }

    public function test_verify_fails_with_wrong_code()
    {
        $svc = $this->app->make(TwoFactorServiceInterface::class);
        $user = new \stdClass();
        $user->id = 12;
        $key = "authmaster_otp:{$user->id}:global";

        Cache::put($key, '123456', 300);

        $this->expectException(\Redoy\AuthMaster\Exceptions\AuthException::class);
        $this->expectExceptionMessage('Invalid code');
        $svc->verify($user, '000000');
    }

    public function test_verify_success()
    {
        $svc = $this->app->make(TwoFactorServiceInterface::class);
        $user = new \stdClass();
        $user->id = 13;
        $key = "authmaster_otp:{$user->id}:global";

        Cache::put($key, '123456', 300);
        $svc->verify($user, '123456');
        
        $this->assertNull(Cache::get($key));
    }

    public function test_is_two_factor_required_for_various_flags()
    {
        $svc = $this->app->make(TwoFactorServiceInterface::class);
        $user = new \stdClass();
        $user->id = 1;

        // globally disabled
        config()->set('authmaster.enable_2fa', false);
        $this->assertFalse($svc->isTwoFactorRequiredFor($user));

        config()->set('authmaster.enable_2fa', true);
        // forced for all
        config()->set('authmaster.otp.force_for_all', true);
        $this->assertTrue($svc->isTwoFactorRequiredFor($user));

        // per-user flag
        config()->set('authmaster.otp.force_for_all', false);
        $user->two_factor_enabled = true;
        $this->assertTrue($svc->isTwoFactorRequiredFor($user));
        $user->two_factor_enabled = false;
        $this->assertFalse($svc->isTwoFactorRequiredFor($user));
    }
}
