<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class EmailToken extends Entity
{
    public string $id;
    public string $user_id;
    public string $token;
    public string $expires_at;
    public bool $is_used;
    public string $created_at;
}
