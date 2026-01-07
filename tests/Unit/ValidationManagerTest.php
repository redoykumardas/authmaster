<?php

namespace Redoy\AuthMaster\Tests\Unit;

use Redoy\AuthMaster\Tests\TestCase;
use Redoy\AuthMaster\Services\ValidationManager;

class ValidationManagerTest extends TestCase
{
    public function test_rules_for_login_contains_expected_keys()
    {
        $vm = new ValidationManager();
        $rules = $vm->rulesForLogin();
        $this->assertArrayHasKey('email', $rules);
        $this->assertArrayHasKey('password', $rules);
    }

    public function test_rules_for_register_contains_password_confirmation_requirement()
    {
        $vm = new ValidationManager();
        $rules = $vm->rulesForRegister();
        $this->assertStringContainsString('confirmed', $rules['password']);
    }

    public function test_rules_for_profile_update_uses_user_id_in_unique_rule()
    {
        $vm = new ValidationManager();
        $user = new \stdClass();
        $user->id = 42;
        $rules = $vm->rulesForProfileUpdate($user);
        $this->assertStringContainsString((string)$user->id, $rules['email']);
    }
}
