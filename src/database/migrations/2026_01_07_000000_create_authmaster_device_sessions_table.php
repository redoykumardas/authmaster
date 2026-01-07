<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        Schema::create('authmaster_device_sessions', function (Blueprint $col) {
            $col->id();
            $col->foreignId('user_id')->constrained()->onDelete('cascade');
            $col->string('device_id')->index();
            $col->string('device_name')->nullable();
            $col->string('ip_address', 45)->nullable();
            $col->text('user_agent')->nullable();
            $col->timestamp('last_active_at')->nullable();
            $col->string('token_id')->nullable()->index();
            $col->json('meta')->nullable();
            $col->timestamps();

            $col->unique(['user_id', 'device_id']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('authmaster_device_sessions');
    }
};
