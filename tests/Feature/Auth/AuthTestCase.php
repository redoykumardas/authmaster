<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Contracts\AuthManagerInterface;
use Redoy\AuthMaster\Contracts\RegistrationServiceInterface;
use Redoy\AuthMaster\DTOs\AuthResult;
use Redoy\AuthMaster\Tests\TestCase;

abstract class AuthTestCase extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Auto-bind RegistrationService mock to prevent controller issues
        $this->bindRegistrationService();
    }

    protected function bindAuth($auth): void
    {
        $this->app->instance(AuthManagerInterface::class, $auth);
    }

    protected function bindRegistrationService(?RegistrationServiceInterface $service = null): void
    {
        if ($service) {
            $this->app->instance(RegistrationServiceInterface::class, $service);
            return;
        }

        // Default mock that returns a successful result
        $mock = $this->getMockBuilder(RegistrationServiceInterface::class)
            ->getMock();

        $mock->method('register')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            token: ['token' => 'abc123'],
            message: 'Registered successfully',
        ));

        $mock->method('verifyEmail')->willReturn(new AuthResult(
            user: (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            message: 'Email verified',
        ));

        $this->app->instance(RegistrationServiceInterface::class, $mock);
    }

    /**
     * Helper to create an AuthResult for testing.
     */
    protected function makeAuthResult(
        $user = null,
        ?array $token = null,
        ?string $message = null,
        bool $emailVerificationRequired = false,
        ?string $emailVerificationMethod = null,
        bool $pendingRegistration = false
    ): AuthResult {
        return new AuthResult(
            user: $user ?? (object) ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            token: $token,
            message: $message,
            emailVerificationRequired: $emailVerificationRequired,
            emailVerificationMethod: $emailVerificationMethod,
            pendingRegistration: $pendingRegistration,
        );
    }
}
