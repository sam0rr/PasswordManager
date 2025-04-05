<?php

namespace Models\src\Services;

use Models\src\Brokers\AuthHistoryBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;

class AuthHistoryService extends BaseService
{
    private AuthHistoryBroker $authHistoryBroker;

    public function __construct()
    {
        $this->authHistoryBroker = new AuthHistoryBroker();
        $this->encryption = new EncryptionService();
        $this->userBroker = new UserBroker();
    }

    public function logSuccess(User $user): void
    {
        $this->authHistoryBroker->logAuthEvent([
            'user_id' => $user->id,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'result' => 'success',
            'location' => 'unknown' // TODO: localisation future
        ]);
    }

    public function logFailure(?string $email = null): void
    {
        $userId = null;

        if (!empty($email)) {
            $user = $this->userBroker->findByEmail($email);
            $userId = $user?->id ?? null;
        }

        $this->authHistoryBroker->logAuthEvent([
            'user_id' => $userId,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'result' => 'fail',
            'location' => 'unknown'
        ]);
    }
}
