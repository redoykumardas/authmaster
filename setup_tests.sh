#!/bin/bash

# Exit on error
set -e

echo "Creating authmaster test structure..."

# Base test folder
mkdir -p tests/Feature/Auth
mkdir -p tests/Feature
mkdir -p tests/Unit/Services
mkdir -p tests/Factories
mkdir -p tests/Traits
mkdir -p tests/Helpers

# Create placeholder Feature test files
touch tests/Feature/Auth/LoginTest.php
touch tests/Feature/Auth/RegisterTest.php
touch tests/Feature/Auth/TwoFactorTest.php
touch tests/Feature/Auth/PasswordResetTest.php
touch tests/Feature/Auth/ProfileUpdateTest.php
touch tests/Feature/Auth/LogoutTest.php
touch tests/Feature/SocialLoginTest.php

# Create placeholder Unit test files for Services
touch tests/Unit/Services/AuthManagerTest.php
touch tests/Unit/Services/DeviceSessionServiceTest.php
touch tests/Unit/Services/PasswordServiceTest.php
touch tests/Unit/Services/SecurityServiceTest.php
touch tests/Unit/Services/SocialLoginServiceTest.php
touch tests/Unit/Services/TokenServiceTest.php
touch tests/Unit/Services/TwoFactorServiceTest.php
touch tests/Unit/Services/ValidationManagerTest.php

# Create Factories
touch tests/Factories/UserFactory.php

# Create Traits test
touch tests/Traits/ApiResponseTest.php

# Create Helpers test
touch tests/Helpers/HelpersTest.php

# Create TestCase.php
cat <<EOT >> tests/TestCase.php
<?php

namespace AuthMaster\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected array \$users = [];
    protected array \$testData = [];

    protected function setUp(): void
    {
        parent::setUp();
        \$this->users = [];

        // Load test data from JSON
        \$jsonPath = __DIR__ . '/data.json';
        if (file_exists(\$jsonPath)) {
            \$this->testData = json_decode(file_get_contents(\$jsonPath), true);
        }
    }

    protected function createUser(array \$attributes = []): object
    {
        \$user = (object) array_merge([
            'id' => count(\$this->users) + 1,
            'name' => 'User ' . (count(\$this->users) + 1),
            'email' => 'user' . (count(\$this->users) + 1) . '@example.com',
            'password' => 'Password123!',
            'two_factor_enabled' => false,
        ], \$attributes);

        \$this->users[] = \$user;
        return \$user;
    }

    protected function createUsers(int \$count): array
    {
        \$users = [];
        for (\$i = 0; \$i < \$count; \$i++) {
            \$users[] = \$this->createUser();
        }
        return \$users;
    }

    protected function getTestData(string \$key): array
    {
        return \$this->testData[\$key] ?? [];
    }

    protected function mockService(string \$class, array \$methods = []): object
    {
        \$mock = \$this->createMock(\$class);
        foreach (\$methods as \$method => \$return) {
            \$mock->method(\$method)->willReturn(\$return);
        }
        return \$mock;
    }
}
EOT

# Create a sample data.json
cat <<EOT >> tests/data.json
{
  "login": [
    {"email": "user1@example.com", "password": "Password123!", "valid": true},
    {"email": "user2@example.com", "password": "wrongpass", "valid": false},
    {"email": "nonexistent@example.com", "password": "Password123!", "valid": false}
  ],
  "register": [
    {"name": "Alice", "email": "alice@example.com", "password": "Password123!", "valid": true},
    {"name": "Bob", "email": "alice@example.com", "password": "Password123!", "valid": false}
  ],
  "passwordReset": [
    {"email": "user1@example.com", "token": "valid-token", "newPassword": "NewPass123!", "valid": true},
    {"email": "user1@example.com", "token": "invalid-token", "newPassword": "NewPass123!", "valid": false}
  ]
}
EOT

echo "✅ Authmaster test structure created successfully!"
