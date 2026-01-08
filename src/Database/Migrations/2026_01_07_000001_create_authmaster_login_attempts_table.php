<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        Schema::create('authmaster_login_attempts', function (Blueprint $col) {
            $col->id();
            $col->string('email')->nullable()->index();
            $col->string('ip_address', 45)->nullable()->index();
            $col->integer('attempts')->default(1);
            $col->timestamp('last_attempt_at')->useCurrent();
            $col->timestamps();

            $col->unique(['email', 'ip_address']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('authmaster_login_attempts');
    }
};
