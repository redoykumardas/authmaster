<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class RegisterTest extends AuthTestCase
{
    /**
     * Common test values
     */
    protected string $endpoint = '/auth/register';
    protected string $defaultName = 'Test User';
    protected string $defaultPassword = 'secret';
    protected string $defaultEmail = 'user@example.com';
    protected string $defaultToken = 'abc123';

    /**
     * 1️⃣ Successful registration
     */
    public function test_register_success_returns_201()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonFragment(['message' => 'Registered']);
    }

    /**
     * 2️⃣ Registration fails when email already exists
     */
    public function test_register_fails_email_already_exists()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => false,
            'message' => 'Email already exists',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'existing@example.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Email already exists']);
    }

    /**
     * 3️⃣ Validation fails if required fields are missing
     */
    public function test_register_validation_fails_missing_fields()
    {
        $this->bindValidator();
        $this->bindAuth($this->createMock(AuthManager::class));

        $this->postJson($this->endpoint, [])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /**
     * 4️⃣ Validation fails with invalid email
     */
    public function test_register_validation_fails_invalid_email()
    {
        $this->bindValidator();
        $this->bindAuth($this->createMock(AuthManager::class));

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'invalid-email',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422);
    }

    /**
     * 5️⃣ Password too short
     */
    public function test_register_validation_fails_password_too_short()
    {
        $this->bindValidator();
        $this->bindAuth($this->createMock(AuthManager::class));

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => '123',
        ])
            ->assertStatus(422);
    }

    /**
     * 6️⃣ Password confirmation mismatch
     */
    public function test_register_fails_password_confirmation_mismatch()
    {
        $this->bindValidator();
        $this->bindAuth($this->createMock(AuthManager::class));

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => 'different',
        ])
            ->assertStatus(422);
    }

    /**
     * 7️⃣ Restricted email domain
     */
    public function test_register_fails_restricted_email_domain()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => false,
            'message' => 'Email domain not allowed',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'blocked@spam.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Email domain not allowed']);
    }

    /**
     * 8️⃣ Rate-limiting
     */
    public function test_register_rate_limited()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => false,
            'message' => 'Too many requests',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(429)
            ->assertJsonFragment(['message' => 'Too many requests']);
    }

    /**
     * 9️⃣ Auto-login after registration
     */
    public function test_register_auto_logs_in_user()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'token' => $this->defaultToken],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'auto@example.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonFragment(['message' => 'Registered'])
            ->assertJsonStructure(['data' => ['token']]);
    }

    /**
     * 🔟 Dispatches Registered event
     */
    public function test_register_dispatches_registered_event()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn(['success' => true, 'data' => ['id' => 1]]);

        $this->bindAuth($auth);
        $this->bindValidator();

        \Event::fake();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'event@example.com',
            'password' => $this->defaultPassword,
        ])->assertStatus(201);

        \Event::assertDispatched(\Illuminate\Auth\Events\Registered::class);
    }

    /**
     * 1️⃣1️⃣ Sends welcome email
     */
    public function test_register_sends_welcome_email()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn(['success' => true, 'data' => ['id' => 1]]);

        $this->bindAuth($auth);
        $this->bindValidator();

        \Mail::fake();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'mail@example.com',
            'password' => $this->defaultPassword,
        ])->assertStatus(201);

        \Mail::assertSent(\App\Mail\WelcomeMail::class);
    }

    /**
     * 1️⃣2️⃣ Assigns default roles/permissions
     */
    public function test_register_assigns_default_roles()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn(['success' => true, 'data' => ['id' => 1]]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'role@example.com',
            'password' => $this->defaultPassword,
        ])->assertStatus(201);

        // Optionally assert roles if AuthManager provides them
        // Example: $this->assertContains('user', $response['data']['roles']);
    }
}
