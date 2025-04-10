<?php

namespace Models\src\Services;

use Models\src\Brokers\AuthHistoryBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Services\Utils\BaseService;

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

    public function hasTooManyAttempts(string $userId, int $minutes = 10, int $maxAttempts = 5): bool
    {
        return $this->authHistoryBroker->countRecentFailures($userId, $minutes) >= $maxAttempts;
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
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $location = $this->fetchLocation($ip);

        return [
            'user_id'    => $userId,
            'ip_address' => $ip,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'result'     => $result,
            'location'   => $location
        ];
    }

    private function fetchLocation(string $ip): string
    {
        $url = "https://ipapi.co/{$ip}/city/";

        $location = @file_get_contents($url);

        if (!$location) {
            return 'unknown';
        }

        return trim($location);
    }

}
