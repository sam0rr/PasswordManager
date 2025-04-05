<?php

namespace Models\src\Services;

use Models\src\Brokers\AuthHistoryBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;

class AuthHistoryService extends BaseService
{
    private AuthHistoryBroker $authHistoryBroker;

    public function __construct(array $auth = [])
    {
        $this->auth = $auth;
        $this->authHistoryBroker = new AuthHistoryBroker();
        $this->userBroker = new UserBroker();
    }

    public function getHistoryForUser(): array
    {
        $userId = $this->auth['user_id'] ?? null;

        if (!$userId) {
            return [];
        }

        return $this->authHistoryBroker->getHistoryForUser($userId);
    }

    // Helpers

    public function logSuccess(User $user): void
    {
        $data = $this->buildAuthData($user->id, 'success');
        $this->authHistoryBroker->logAuthEvent($data);
    }

    public function logFailure(?string $email): void
    {
        if (empty($email)) {
            return;
        }

        $user = $this->userBroker->findByEmail($email);
        if (!$user) {
            return;
        }

        $data = $this->buildAuthData($user->id, 'fail');
        $this->authHistoryBroker->logAuthEvent($data);
    }

    private function buildAuthData(?string $userId, string $result): array
    {
        return [
            'user_id'    => $userId,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'result'     => $result,
            'location'   => 'unknown'
        ];
    }
}
