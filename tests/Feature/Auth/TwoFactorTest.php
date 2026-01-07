<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Exceptions\AuthException;
use Redoy\AuthMaster\Services\AuthManager;

class TwoFactorTest extends AuthTestCase
{
    public function test_verify_2fa_fails()
    {
        $auth = $this->createMock(AuthManagerInterface::class);
        $auth->method('verifyTwoFactor')->willThrowException(new AuthException('Invalid code', 422));

        $this->bindAuth($auth);

        $this->postJson('/api/auth/2fa/verify', [
            'code' => '1234',
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Invalid code']);
    }
}
