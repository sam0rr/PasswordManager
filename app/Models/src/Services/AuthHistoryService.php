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
        $this->encryption = new EncryptionService();
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
        $this->authHistoryBroker->logAuthEvent(
            $this->buildEncryptedAuthData($user->id, 'success')
        );
    }

    public function logFailure(?string $email = null): void
    {
        $userId = null;
        if (!empty($email)) {
            $user = $this->userBroker->findByEmail($email);
            $userId = $user?->id ?? null;
        }

        $this->authHistoryBroker->logAuthEvent(
            $this->buildEncryptedAuthData($userId, 'fail')
        );
    }

    private function buildEncryptedAuthData(?string $userId, string $result): array
    {
        $key = $this->encryption->getUserKeyFromContext();

        return [
            'user_id'    => $userId,
            'ip_address' => $this->encryption->encryptWithUserKey($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', $key),
            'user_agent' => $this->encryption->encryptWithUserKey($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', $key),
            'result'     => $result,
            'location'   => $this->encryption->encryptWithUserKey("unknown", $key)
        ];
    }
}
