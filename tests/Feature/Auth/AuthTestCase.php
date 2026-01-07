<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Services\AuthManager;
use Redoy\AuthMaster\Services\ValidationManager;

abstract class AuthTestCase extends TestCase
{
    protected function bindValidator(): void
    {
        $methods = [
            'rulesForLogin',
            'rulesForRegister',
            'rulesForPasswordEmail',
            'rulesForPasswordReset',
            'rulesFor2FASend',
            'rulesFor2FAVerify',
            'rulesForProfileUpdate',
            'rulesForChangePassword',
        ];

        $validator = $this->getMockBuilder(ValidationManager::class)
            ->onlyMethods($methods)
            ->getMock();

        foreach ($methods as $method) {
            $validator->method($method)->willReturn([]);
        }

        $this->app->instance(ValidationManager::class, $validator);
    }

    protected function bindAuth(AuthManager $auth): void
    {
        $this->app->instance(AuthManager::class, $auth);
    }
}
