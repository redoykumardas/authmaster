<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        // Update device sessions with more fields
        Schema::table('authmaster_device_sessions', function (Blueprint $table) {
            $table->string('browser')->nullable()->after('user_agent');
            $table->string('os')->nullable()->after('browser');
            $table->string('device_type')->nullable()->after('os'); // desktop, mobile, tablet
            $table->string('location')->nullable()->after('device_type');
        });

        // Add device_id to login attempts for device-based lockout
        Schema::table('authmaster_login_attempts', function (Blueprint $table) {
            $table->string('device_id')->nullable()->index()->after('ip_address');
        });

        // New table for registration attempts tracking
        Schema::create('authmaster_registration_attempts', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->index();
            $table->string('device_id')->nullable()->index();
            $table->integer('attempts')->default(1);
            $table->timestamp('last_attempt_at')->useCurrent();
            $table->timestamps();

            $table->unique(['ip_address', 'device_id'], 'reg_attempts_device_unique');
        });
    }

    public function down()
    {
        Schema::table('authmaster_device_sessions', function (Blueprint $table) {
            $table->dropColumn(['browser', 'os', 'device_type', 'location']);
        });

        Schema::table('authmaster_login_attempts', function (Blueprint $table) {
            $table->dropIndex(['device_id']);
            $table->dropColumn('device_id');
        });

        Schema::dropIfExists('authmaster_registration_attempts');
    }
};
