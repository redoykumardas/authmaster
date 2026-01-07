<?php

namespace Redoy\AuthMaster\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DeviceSession extends Model
{
    protected $table = 'authmaster_device_sessions';

    protected $fillable = [
        'user_id',
        'device_id',
        'device_name',
        'ip_address',
        'user_agent',
        'browser',
        'os',
        'device_type',
        'location',
        'last_active_at',
        'token_id',
        'meta',
    ];

    protected $casts = [
        'meta' => 'array',
        'last_active_at' => 'datetime',
    ];

    public $timestamps = true;

    public function user(): BelongsTo
    {
        return $this->belongsTo(config('auth.providers.users.model'));
    }
}
