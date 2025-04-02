<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class AuthHistory extends Entity
{
    public int $id;
    public string $userId;
    public string $ipAddress;
    public string $userAgent;
    public string $authTimestamp;
    public string $result;
    public string $location;
    public int $failedLogins;
    public ?string $accountLockUntil;
}
