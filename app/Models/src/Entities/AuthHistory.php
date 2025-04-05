<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class AuthHistory extends Entity
{
    public int $id;
    public string $user_id;
    public string $ip_address;
    public string $user_agent;
    public string $auth_timestamp;
    public string $result;
    public string $location;
}
