<?php

namespace Models\src\Entities;

use Models\Core\Entity;

final class UserVerify extends Entity
{
    public string $id;
    public string $user_id;
    public string $method;
    public bool $is_active;
    public bool $is_first_verified;
    public string $otp_secret;
    public ?string $otp_created_at;
    public string $last_verified;
    public string $created_at;
    public string $updated_at;
    public bool $grace_period_enabled;
}
