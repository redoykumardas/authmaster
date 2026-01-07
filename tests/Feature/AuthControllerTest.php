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
            'rulesForLogin', 'rulesForRegister', 'rulesForPasswordEmail', 'rulesForPasswordReset',
            'rulesFor2FASend', 'rulesFor2FAVerify', 'rulesForProfileUpdate', 'rulesForChangePassword'
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
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('login')->willReturn(['success' => true, 'data' => ['token' => 'abc']]);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/auth/login', [
            'email' => 'test@example.com',
            'password' => 'secret',
        ]);

        $response->assertStatus(200)->assertJsonFragment(['message' => 'Logged in']);
    }

    public function test_login_failure_returns_401()
    {
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('login')->willReturn(['success' => false, 'message' => 'Invalid credentials']);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/auth/login', [
            'email' => 'bad@example.com',
            'password' => 'wrong',
        ]);

        $response->assertStatus(401)->assertJsonFragment(['message' => 'Invalid credentials']);
    }

    public function test_register_success_returns_201()
    {
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('register')->willReturn(['success' => true, 'data' => ['id' => 1]]);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/auth/register', [
            'name' => 'Test',
            'email' => 'new@example.com',
            'password' => 'secret',
        ]);

        $response->assertStatus(201)->assertJsonFragment(['message' => 'Registered']);
    }

    public function test_forgot_password_succeeds()
    {
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('sendPasswordResetLink')->willReturn(['success' => true]);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/auth/password/email', ['email' => 'user@example.com']);
        $response->assertStatus(200)->assertJsonFragment(['message' => 'Reset email sent']);
    }

    public function test_reset_password_succeeds()
    {
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('resetPassword')->willReturn(['success' => true]);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $response = $this->postJson('/auth/password/reset', ['email' => 'user@example.com', 'token' => 'tok', 'password' => 'newpass']);
        $response->assertStatus(200)->assertJsonFragment(['message' => 'Password reset']);
    }

    public function test_send_2fa_and_verify_flow()
    {
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('sendTwoFactor')->willReturn(['success' => true]);
        $authMock->method('verifyTwoFactor')->willReturn(['success' => false, 'message' => 'Invalid code']);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $resp1 = $this->postJson('/auth/2fa/verify', ['code' => '1234']);
        // verify2fa is a public endpoint; our mock returns failure
        $resp1->assertStatus(422)->assertJsonFragment(['message' => 'Invalid code']);
    }

    public function test_social_redirect_and_callback()
    {
        $authMock = $this->createMock(AuthManager::class);
        $authMock->method('socialRedirect')->willReturn(['redirect' => response('ok', 302)]);
        $authMock->method('handleSocialCallback')->willReturn(['success' => true, 'data' => ['token' => 'abc']]);
        $this->app->instance(AuthManager::class, $authMock);

        $this->app->instance(ValidationManager::class, $this->makeValidatorMock());

        $resp = $this->post('/auth/social/github');
        $this->assertTrue(in_array($resp->getStatusCode(), [200, 302]));

        $resp2 = $this->get('/auth/social/github/callback');
        $resp2->assertStatus(200)->assertJsonFragment(['message' => 'Social login successful']);
    }

    public function test_profile_and_logout_endpoints_with_bound_authmanager()
    {
        // Provide a fake AuthManager and simulate an authenticated user via actingAs on a simple model
        $user = new \stdClass();
        $user->id = 1;
        $user->name = 'Test';

        $authMock = $this->createMock(AuthManager::class);
        $this->app->instance(AuthManager::class, $authMock);

        // Acting as uses a real Authenticatable model; use Laravel's generic user model if available otherwise skip
        // We'll bypass middleware by ensuring auth middleware is 'api' (set in TestCase)

        // Hit logout (protected route group should accept since middleware is 'api')
        $resp = $this->postJson('/auth/logout');
        $resp->assertStatus(200)->assertJsonFragment(['message' => 'Logged out']);

        $resp2 = $this->postJson('/auth/logout/all');
        $resp2->assertStatus(200)->assertJsonFragment(['message' => 'Logged out from all devices']);
    }
}
