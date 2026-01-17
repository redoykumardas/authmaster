<?php

namespace Redoy\AuthMaster\Tests\Feature\Auth;

use Illuminate\Support\Facades\Route;
use Redoy\AuthMaster\Models\DeviceSession;
use Redoy\AuthMaster\Tests\TestCase;

class DeviceManagementTest extends TestCase
{
    /** @test */
    public function test_can_list_devices()
    {
        $user = $this->createUser();
        $this->actingAs($user);

        // Create a few mock sessions
        DeviceSession::create([
            'user_id' => $user->id,
            'device_id' => 'device_1',
            'device_name' => 'iPhone 13',
            'ip_address' => '1.1.1.1',
            'last_active_at' => now(),
        ]);

        DeviceSession::create([
            'user_id' => $user->id,
            'device_id' => 'device_2',
            'device_name' => 'Windows PC',
            'ip_address' => '2.2.2.2',
            'last_active_at' => now()->subDay(),
        ]);

        $response = $this->getJson('/api/auth/devices');

        $response->assertStatus(200)
            ->assertJsonCount(2, 'data.devices')
            ->assertJsonFragment(['device_id' => 'device_1'])
            ->assertJsonFragment(['device_id' => 'device_2']);
    }

    /** @test */
    public function test_can_remove_device()
    {
        $user = $this->createUser();
        $this->actingAs($user);

        DeviceSession::create([
            'user_id' => $user->id,
            'device_id' => 'device_to_remove',
            'device_name' => 'Temporary Device',
            'ip_address' => '3.3.3.3',
            'last_active_at' => now(),
        ]);

        $this->assertDatabaseHas('authmaster_device_sessions', [
            'device_id' => 'device_to_remove'
        ]);

        $response = $this->deleteJson('/api/auth/devices/device_to_remove');

        $response->assertStatus(200)
            ->assertJsonFragment(['message' => 'Device removed successfully']);

        $this->assertDatabaseMissing('authmaster_device_sessions', [
            'device_id' => 'device_to_remove'
        ]);
    }

    protected function createUser()
    {
        $model = config('auth.providers.users.model');
        return $model::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => bcrypt('password'),
        ]);
    }
}
