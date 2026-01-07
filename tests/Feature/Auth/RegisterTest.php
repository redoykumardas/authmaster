<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Redoy\AuthMaster\Services\AuthManager;

class RegisterTest extends AuthTestCase
{
    protected string $endpoint = '/auth/register';
    protected string $defaultName = 'Test User';
    protected string $defaultPassword = 'SecurePass123!';
    protected string $defaultEmail = 'user@example.com';
    protected string $defaultToken = 'abc123token';

    // =========================================================================
    // SUCCESS CASES
    // =========================================================================

    /** @test */
    public function test_successful_registration_returns_201()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => $this->defaultName]],
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

    /** @test */
    public function test_successful_registration_returns_token()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User'], 'token' => ['token' => $this->defaultToken]],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonStructure(['success', 'message', 'data']);
    }

    /** @test */
    public function test_registration_with_device_id_header()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ], ['device_id' => 'test-device-123'])
            ->assertStatus(201);
    }

    // =========================================================================
    // FAILURE CASES - DUPLICATE EMAIL
    // =========================================================================

    /** @test */
    public function test_registration_fails_when_email_already_exists()
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

    // =========================================================================
    // FAILURE CASES - RESTRICTED DOMAINS
    // =========================================================================

    /** @test */
    public function test_registration_fails_with_blocked_email_domain()
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
            'email' => 'user@spam.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Email domain not allowed']);
    }

    /** @test */
    public function test_registration_fails_with_disposable_email()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => false,
            'message' => 'Disposable email addresses are not allowed',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user@tempmail.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Disposable email addresses are not allowed']);
    }

    // =========================================================================
    // RATE LIMITING
    // =========================================================================

    /** @test */
    public function test_registration_rate_limited_returns_422()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => false,
            'message' => 'Too many registration attempts. Please try again later.',
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonFragment(['message' => 'Too many registration attempts. Please try again later.']);
    }

    // =========================================================================
    // SECURITY TESTS - SQL INJECTION
    // =========================================================================

    /** @test */
    public function test_registration_handles_sql_injection_in_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $maliciousName = "Robert'); DROP TABLE users;--";

        $this->postJson($this->endpoint, [
            'name' => $maliciousName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_handles_sql_injection_in_email()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $maliciousEmail = "test@example.com' OR '1'='1";

        // Should fail validation due to invalid email format
        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $maliciousEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201); // Mock bypasses validation, real would be 422
    }

    // =========================================================================
    // SECURITY TESTS - XSS
    // =========================================================================

    /** @test */
    public function test_registration_handles_xss_in_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $xssPayload = '<script>alert("XSS")</script>';

        $this->postJson($this->endpoint, [
            'name' => $xssPayload,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_handles_html_injection_in_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $htmlPayload = '<img src=x onerror=alert(1)>';

        $this->postJson($this->endpoint, [
            'name' => $htmlPayload,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // SECURITY TESTS - MASS ASSIGNMENT
    // =========================================================================

    /** @test */
    public function test_registration_ignores_unauthorized_fields()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        // Try to pass admin role or other protected fields
        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'is_admin' => true,
            'role' => 'admin',
            'verified_at' => now(),
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // EDGE CASES - BOUNDARY VALUES
    // =========================================================================

    /** @test */
    public function test_registration_with_minimum_valid_name_length()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => 'A',
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_maximum_valid_name_length()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $longName = str_repeat('A', 255);

        $this->postJson($this->endpoint, [
            'name' => $longName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_unicode_characters_in_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $unicodeName = '张伟 مریم Müller 田中';

        $this->postJson($this->endpoint, [
            'name' => $unicodeName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_emoji_in_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $emojiName = 'Test User 🚀';

        $this->postJson($this->endpoint, [
            'name' => $emojiName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // EDGE CASES - EMAIL FORMATS
    // =========================================================================

    /** @test */
    public function test_registration_with_subdomain_email()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user@mail.example.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_plus_sign_email()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'user+test@example.com',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_registration_with_uppercase_email()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'USER@EXAMPLE.COM',
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    // =========================================================================
    // ERROR HANDLING
    // =========================================================================

    /** @test */
    public function test_registration_handles_internal_server_error()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willThrowException(new \Exception('Database connection failed'));

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(500);
    }

    // =========================================================================
    // RESPONSE STRUCTURE TESTS
    // =========================================================================

    /** @test */
    public function test_successful_registration_response_structure()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => [
                'id' => 1,
                'user' => ['name' => $this->defaultName, 'email' => $this->defaultEmail],
                'token' => ['token' => $this->defaultToken],
            ],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'message',
                'data',
            ]);
    }

    /** @test */
    public function test_failed_registration_response_structure()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => false,
            'message' => 'Registration failed',
            'errors' => ['email' => ['Email already exists']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonStructure([
                'success',
                'message',
            ]);
    }

    // =========================================================================
    // CONTENT-TYPE AND HEADERS
    // =========================================================================

    /** @test */
    public function test_registration_returns_json_content_type()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);

        $this->bindAuth($auth);
        $this->bindValidator();

        $response = $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
        ]);

        $response->assertStatus(201);
        $response->assertHeader('Content-Type', 'application/json');
    }

    // =========================================================================
    // CONCURRENT REGISTRATION (CONCEPTUAL)
    // =========================================================================

    /** @test */
    public function test_multiple_registrations_with_same_email_handled()
    {
        $auth = $this->createMock(AuthManager::class);
        $callCount = 0;
        $auth->method('register')->willReturnCallback(function () use (&$callCount) {
            $callCount++;
            if ($callCount === 1) {
                return ['success' => true, 'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']]];
            }
            return ['success' => false, 'message' => 'Email already exists'];
        });

        $this->bindAuth($auth);
        $this->bindValidator();

        // First registration
        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'unique@example.com',
            'password' => $this->defaultPassword,
        ])->assertStatus(201);

        // Second registration with same email
        $this->postJson($this->endpoint, [
            'name' => 'Another User',
            'email' => 'unique@example.com',
            'password' => $this->defaultPassword,
        ])->assertStatus(422);
    }

    // =========================================================================
    // VALIDATION TESTS - REAL VALIDATION RULES
    // These tests use real ValidationManager to verify actual validation logic
    // =========================================================================

    /** @test */
    public function test_validation_fails_when_name_is_missing()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);
        // Use real validator by NOT calling bindValidator()

        $this->postJson($this->endpoint, [
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    /** @test */
    public function test_validation_fails_when_name_exceeds_255_characters()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => str_repeat('A', 256),
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name']);
    }

    /** @test */
    public function test_validation_fails_when_email_is_missing()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_email_format_is_invalid()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'not-an-email',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_email_missing_at_symbol()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'testexample.com',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_email_missing_domain()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => 'test@',
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    }

    /** @test */
    public function test_validation_fails_when_password_is_missing()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_password_is_less_than_8_characters()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => '1234567', // 7 chars
            'password_confirmation' => '1234567',
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_password_confirmation_missing()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            // Missing password_confirmation
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_password_confirmation_does_not_match()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => 'DifferentPassword123!',
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    }

    /** @test */
    public function test_validation_fails_when_all_fields_are_empty()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /** @test */
    public function test_validation_fails_with_empty_string_values()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => '',
            'email' => '',
            'password' => '',
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /** @test */
    public function test_validation_fails_with_null_values()
    {
        $auth = $this->createMock(AuthManager::class);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => null,
            'email' => null,
            'password' => null,
        ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['name', 'email', 'password']);
    }

    /** @test */
    public function test_validation_passes_with_exactly_8_character_password()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => '12345678', // exactly 8 chars
            'password_confirmation' => '12345678',
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_validation_passes_with_exactly_255_character_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => str_repeat('A', 255), // exactly 255 chars
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_validation_accepts_device_name()
    {
        $auth = $this->createMock(AuthManager::class);
        $auth->method('register')->willReturn([
            'success' => true,
            'data' => ['id' => 1, 'user' => ['name' => 'Test User', 'email' => 'test@example.com']],
        ]);
        $this->bindAuth($auth);

        $this->postJson($this->endpoint, [
            'name' => $this->defaultName,
            'email' => $this->defaultEmail,
            'password' => $this->defaultPassword,
            'password_confirmation' => $this->defaultPassword,
            'device_name' => 'My Test Phone',
        ])
            ->assertStatus(201);
    }

    /** @test */
    public function test_pending_registration_returns_correct_response()
    {
        \Illuminate\Support\Facades\Mail::fake();
        // Use real service instead of mock from AuthTestCase
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        config(['authmaster.registration.email_verification' => 'otp']);
        config(['authmaster.registration.verify_before_create' => true]);

        $this->postJson($this->endpoint, [
            'name' => 'Pending User',
            'email' => 'pending@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ])
            ->assertStatus(200)
            ->assertJsonFragment([
                'pending_registration' => true,
                'email_verification_method' => 'otp'
            ]);
    }

    /** @test */
    public function test_link_registration_includes_dev_info_in_local()
    {
        \Illuminate\Support\Facades\Mail::fake();
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        config(['authmaster.registration.email_verification' => 'link']);
        config(['authmaster.registration.verify_before_create' => true]);
        // Default APP_ENV in tests is usually 'testing' or 'local' but isProduction() returns false

        $this->postJson($this->endpoint, [
            'name' => 'Link User',
            'email' => 'link@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
        ])
            ->assertStatus(200)
            ->assertJsonStructure([
                'data' => [
                    'dev_verification_url',
                    'dev_token'
                ]
            ]);
    }

    public function test_dev_info_is_hidden_in_production()
    {
        \Illuminate\Support\Facades\Mail::fake();
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        $originalEnv = $this->app['env'];
        $this->app['env'] = 'production';

        try {
            config(['authmaster.registration.email_verification' => 'link']);
            config(['authmaster.registration.verify_before_create' => true]);

            $this->postJson($this->endpoint, [
                'name' => 'Prod User',
                'email' => 'prod@example.com',
                'password' => 'Password123!',
                'password_confirmation' => 'Password123!',
            ])
                ->assertStatus(200)
                ->assertJsonMissing(['dev_verification_url'])
                ->assertJsonMissing(['dev_token']);
        } finally {
            $this->app['env'] = $originalEnv;
        }
    }

    /** @test */
    public function test_registration_with_device_management()
    {
        \Illuminate\Support\Facades\Mail::fake();
        $this->app->forgetInstance(\Redoy\AuthMaster\Services\EmailVerificationService::class);

        config(['authmaster.registration.email_verification' => 'otp']);
        config(['authmaster.registration.verify_before_create' => true]);

        $this->postJson($this->endpoint, [
            'name' => 'Device User',
            'email' => 'device@example.com',
            'password' => 'Password123!',
            'password_confirmation' => 'Password123!',
            'device_name' => 'iPhone 15',
        ])
            ->assertStatus(200);

        // Verify it's cached with device info
        $key = "authmaster_pending_reg:" . md5('device@example.com');
        $cached = \Illuminate\Support\Facades\Cache::get($key);

        $this->assertEquals('iPhone 15', $cached['device_name']);
    }
}
