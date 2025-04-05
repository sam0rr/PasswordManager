<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class PasswordSharing extends Entity
{
    public string $id;
    public string $password_id;
    public string $owner_id;
    public string $shared_id;
    public string $status;
    public string $expires_at;
    public string $created_at;
    public string $updated_at;
}
