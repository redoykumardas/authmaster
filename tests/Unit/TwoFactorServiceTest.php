<?php

namespace Redoy\AuthMaster\Tests\Unit;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Services\TwoFactorService;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Cache;

class TwoFactorServiceTest extends TestCase
{
    public function test_generate_and_send_stores_code_and_sends_mail()
    {
        Mail::fake();

        $svc = new TwoFactorService();
        $user = new \stdClass();
        $user->id = 10;
        $user->email = 'user@example.com';

        $res = $svc->generateAndSend($user, 'device-x');

        $this->assertTrue($res['success']);

        $key = (new \ReflectionClass($svc))->getMethod('cacheKey')->invoke($svc, $user->id, 'device-x');
        $this->assertNotNull(Cache::get($key));

        Mail::assertSent(\Redoy\AuthMaster\Mail\SendOtpMail::class);
    }

    public function test_verify_success_and_failure_and_expiry()
    {
        $svc = new TwoFactorService();
        $user = new \stdClass();
        $user->id = 11;

        $key = (new \ReflectionClass($svc))->getMethod('cacheKey')->invoke($svc, $user->id, 'global');

        // No code in cache => expiry
        $res = $svc->verify($user, '000000');
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('expired', $res['message']);

        // Put a code and verify wrong code
        Cache::put($key, '123456', 300);
        $res2 = $svc->verify($user, '000000');
        $this->assertFalse($res2['success']);
        $this->assertStringContainsString('Invalid', $res2['message']);

        // Correct code
        $res3 = $svc->verify($user, '123456');
        $this->assertTrue($res3['success']);
        $this->assertNull(Cache::get($key));
    }

    public function test_is_two_factor_required_for_various_flags()
    {
        $svc = new TwoFactorService();
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
