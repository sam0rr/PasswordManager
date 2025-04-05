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
        $key = $this->auth['user_key'] ?? null;

        if (!$userId || !$key) {
            return [];
        }

        return $this->authHistoryBroker->getHistoryForUser($userId, $key);
    }

    //Helpers

    public function logSuccess(User $user, string $key): void
    {
        $data = $this->buildEncryptedAuthData($user->id, 'success', $key);
        $this->authHistoryBroker->logAuthEvent($data, $key);
    }

    public function logFailure(?string $email): void
    {
        $key = null;

        if (empty($email)) {
            return;
        }

        $user = $this->userBroker->findByEmail($email);
        if (!$user) {
            return;
        }

        $userId = $user->id;

        $data = [
            'user_id' => $userId,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'result' => 'fail',
            'location' => 'unknown'
        ];

        $this->authHistoryBroker->logAuthEvent($data, $key);
    }

    public function updateHistoryWithNewKey(string $userId, string $oldKey, string $newKey): void
    {
        $rows = $this->authHistoryBroker->getHistoryForUser($userId, $oldKey);

        foreach ($rows as $history) {
            $updates = [
                'ip_address' => $this->encryption->encryptWithUserKey($history->ip_address, $newKey),
                'user_agent' => $this->encryption->encryptWithUserKey($history->user_agent, $newKey),
                'location' => $this->encryption->encryptWithUserKey($history->location, $newKey)
            ];

            $this->authHistoryBroker->updateAuthHistory($history->id, $updates);
        }
    }

    private function buildEncryptedAuthData(?string $userId, string $result, string $key): array
    {
        return [
            'user_id'    => $userId,
            'ip_address' => $this->encryption->encryptWithUserKey($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', $key),
            'user_agent' => $this->encryption->encryptWithUserKey($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', $key),
            'result'     => $result,
            'location'   => $this->encryption->encryptWithUserKey("unknown", $key)
        ];
    }
}
