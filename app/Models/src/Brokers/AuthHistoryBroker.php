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

    public function logAuthEvent(array $data, ?string $key = null): AuthHistory
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
        return $key ? $this->decryptHistory($history, $key) : $history;
    }

    public function getHistoryForUser(string $userId, string $key): array
    {
        $rows = $this->select(
            "SELECT * FROM auth_history WHERE user_id = ? ORDER BY auth_timestamp DESC",
            [$userId]
        );

        return array_map(function ($row) use ($key) {
            $history = AuthHistory::build($row);
            return $this->decryptHistory($history, $key);
        }, $rows);
    }

    public function updateAuthHistory(string $id, array $updates): void
    {
        if (empty($updates)) {
            return;
        }

        $columns = [];
        $values = [];

        foreach ($updates as $column => $value) {
            $columns[] = "$column = ?";
            $values[] = $value;
        }

        $values[] = $id;

        $sql = "UPDATE auth_history SET " . implode(", ", $columns) . " WHERE id = ?";
        $this->query($sql, $values);
    }

    private function decryptHistory(AuthHistory $history, string $userKey): AuthHistory
    {
        $history->ip_address = $this->encryption->decryptWithUserKey($history->ip_address, $userKey);
        $history->user_agent = $this->encryption->decryptWithUserKey($history->user_agent, $userKey);
        $history->location = $this->encryption->decryptWithUserKey($history->location, $userKey);

        return $history;
    }
}
