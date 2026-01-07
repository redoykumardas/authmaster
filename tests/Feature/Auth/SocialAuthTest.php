<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\Services\AuthManager;

class SocialAuthTest extends AuthTestCase
{
    public function test_social_redirect_and_callback()
    {
        $auth = $this->createMock(AuthManagerInterface::class);
        $auth->method('socialRedirect')->willReturn(new AuthResult(
            user: redirect('http://github.com/login'),
            message: 'Redirecting'
        ));

        $auth->method('handleSocialCallback')->willReturn(new AuthResult(
            user: ['email' => 'social@example.com'],
            token: ['token' => 'abc'],
            message: 'Social login successful'
        ));

        $this->bindAuth($auth);

        $this->post('/api/auth/social/github')
            ->assertStatus(302);

        $this->get('/api/auth/social/github/callback')
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Social login successful']);
    }
}
