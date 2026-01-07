<?php

namespace Redoy\AuthMaster\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Mail;
use Redoy\AuthMaster\Mail\VerificationLinkMail;

class SendVerificationLinkJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        protected $user,
        protected string $url
    ) {
        $this->onQueue(config('authmaster.otp.queue_name', 'default'));
    }

    public function handle()
    {
        Mail::to($this->user->email)->send(new VerificationLinkMail($this->user, $this->url));
    }
}
