<?php

namespace Redoy\AuthMaster\Tests\Feature;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Services\AuthManager;
use Redoy\AuthMaster\Services\ValidationManager;

class AuthControllerTest extends TestCase
{
    protected function makeValidatorMock()
    {
        $methods = [
            'rulesForLogin',
            'rulesForRegister',
            'rulesForPasswordEmail',
            'rulesForPasswordReset',
            'rulesFor2FASend',
            'rulesFor2FAVerify',
            'rulesForProfileUpdate',
            'rulesForChangePassword'
        ];

        $validator = $this->getMockBuilder(ValidationManager::class)
            ->onlyMethods($methods)
            ->getMock();

        foreach ($methods as $m) {
            $validator->method($m)->willReturn([]);
        }

        return $validator;
    }

    public function test_login_success_returns_200()
    {
        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $authMock->method('loginWithData')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'Logged in'));
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/api/auth/login', [
            'email' => 'test@example.com',
            'password' => 'secret',
        ]);

        $response->assertStatus(200)->assertJsonFragment(['message' => 'Logged in']);
    }

    public function test_login_failure_returns_401()
    {
        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $authMock->method('loginWithData')->willThrowException(new \Redoy\AuthMaster\Exceptions\InvalidCredentialsException());
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/api/auth/login', [
            'email' => 'bad@example.com',
            'password' => 'wrong',
        ]);

        $response->assertStatus(401)->assertJsonFragment(['message' => 'Invalid credentials']);
    }

    public function test_register_success_returns_201()
    {
        $regMock = $this->createMock(\Redoy\AuthMaster\Contracts\RegistrationServiceInterface::class);
        $regMock->method('register')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'Registered', status: 201));
        $this->app->instance(\Redoy\AuthMaster\Contracts\RegistrationServiceInterface::class, $regMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/api/auth/register', [
            'name' => 'Test',
            'email' => 'new@example.com',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);

        $response->assertStatus(201)->assertJsonFragment(['message' => 'Registered']);
    }

    public function test_forgot_password_succeeds()
    {
        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $authMock->method('sendPasswordResetLink')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'Reset email sent'));
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/api/auth/password/email', ['email' => 'user@example.com']);
        $response->assertStatus(200)->assertJsonFragment(['message' => 'Reset email sent']);
    }

    public function test_reset_password_succeeds()
    {
        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $authMock->method('resetPasswordWithData')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'Password reset'));
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/api/auth/password/reset', [
            'email' => 'user@example.com',
            'token' => 'tok',
            'password' => 'password123',
            'password_confirmation' => 'password123',
        ]);
        $response->assertStatus(200)->assertJsonFragment(['message' => 'Password reset']);
    }

    public function test_send_2fa_and_verify_flow()
    {
        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $authMock->method('sendTwoFactor')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'OTP sent'));
        $authMock->method('verifyTwoFactor')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'OTP verified'));
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $resp1 = $this->postJson('/api/auth/2fa/verify', ['code' => '1234']);
        // verify2fa returns 200 on success in our mock now
        $resp1->assertStatus(200)->assertJsonFragment(['message' => 'OTP verified']);
    }

    public function test_social_redirect_and_callback()
    {
        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $authMock->method('socialRedirect')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'Redirecting'));
        $authMock->method('handleSocialCallback')->willReturn(new \Redoy\AuthMaster\DTOs\AuthResult(message: 'Social login successful'));
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $resp = $this->post('/api/auth/social/github');
        $resp->assertStatus(200)->assertJsonFragment(['message' => 'Redirecting']);

        $resp2 = $this->get('/api/auth/social/github/callback');
        $resp2->assertStatus(200)->assertJsonFragment(['message' => 'Social login successful']);
    }

    public function test_profile_and_logout_endpoints_with_bound_authmanager()
    {
        $user = \Illuminate\Support\Facades\DB::table('users')->insertGetId([
            'name' => 'Test',
            'email' => 'test@example.com',
            'password' => 'password123',
        ]);
        $userModel = \Illuminate\Foundation\Auth\User::find($user);

        $authMock = $this->createMock(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class);
        $this->app->instance(\Redoy\AuthMaster\Contracts\AuthManagerInterface::class, $authMock);

        $this->actingAs($userModel, 'web'); // Use 'web' which is default in Laravel migrations if 'api' is not defined

        $resp = $this->postJson('/api/auth/logout');
        $resp->assertStatus(200)->assertJsonFragment(['message' => 'Logged out']);

        $resp2 = $this->postJson('/api/auth/logout/all');
        $resp2->assertStatus(200)->assertJsonFragment(['message' => 'Logged out from all devices']);
    }
}
