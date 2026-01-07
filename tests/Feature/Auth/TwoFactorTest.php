<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class TwoFactorTest extends AuthTestCase
{
    public function test_verify_2fa_fails()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('verifyTwoFactor')->willReturn([
            'success' => false,
            'message' => 'Invalid code',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson('/auth/2fa/verify', [
            'code' => '1234',
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Invalid code']);
    }
}
