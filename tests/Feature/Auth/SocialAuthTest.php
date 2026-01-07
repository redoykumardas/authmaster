<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class SocialAuthTest extends AuthTestCase
{
    public function test_social_redirect_and_callback()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('socialRedirect')->willReturn([
            'redirect' => response('ok', 302),
        ]);

        $auth->method('handleSocialCallback')->willReturn([
            'success' => true,
            'data' => ['token' => 'abc'],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->post('/auth/social/github')
            ->assertStatus(302);

        $this->get('/auth/social/github/callback')
            ->assertStatus(200)
            ->assertJsonFragment(['message' => 'Social login successful']);
    }
}
