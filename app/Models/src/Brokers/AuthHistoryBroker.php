<?php

namespace Models\src\Brokers;

use Models\src\Entities\AuthHistory;
use Models\src\Services\EncryptionService;
use Zephyrus\Database\DatabaseBroker;

class AuthHistoryBroker extends DatabaseBroker
{
    private EncryptionService $encryption;

    public function __construct()
    {
        parent::__construct();
        $this->encryption = new EncryptionService();
    }

    public function logAuthEvent(array $data): AuthHistory
    {
        $row = $this->selectSingle(
            "INSERT INTO auth_history (user_id, ip_address, user_agent, result, location)
             VALUES (?, ?, ?, ?, ?)
             RETURNING *;",
            [
                $data['user_id'],
                $data['ip_address'],
                $data['user_agent'],
                $data['result'],
                $data['location']
            ]
        );

        $history = AuthHistory::build($row);
        return $this->decryptHistory($history);
    }

    public function getHistoryForUser(string $userId): array
    {
        $rows = $this->select(
            "SELECT * FROM auth_history WHERE user_id = ? ORDER BY auth_timestamp DESC",
            [$userId]
        );

        return array_map(function ($row) {
            $history = AuthHistory::build($row);
            return $this->decryptHistory($history);
        }, $rows);
    }

    private function decryptHistory(AuthHistory $history): AuthHistory
    {
        $key = $this->encryption->getUserKeyFromContext();

        $history->ip_address = $this->encryption->decryptWithUserKey($history->ip_address, $key);
        $history->user_agent = $this->encryption->decryptWithUserKey($history->user_agent, $key);
        $history->location = $this->encryption->decryptWithUserKey($history->location, $key);

        return $history;
    }
}
