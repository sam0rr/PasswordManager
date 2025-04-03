<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class UserAuth extends Entity
{
    public string $id;
    public string $user_id;
    public string $method;
    public bool $is_active;
    public string $otp_secret;
    public string $last_verified;
    public string $created_at;
    public string $updated_at;
}
