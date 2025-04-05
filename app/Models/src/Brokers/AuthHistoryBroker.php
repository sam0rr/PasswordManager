<?php

namespace Models\src\Brokers;

use Models\src\Entities\AuthHistory;
use Zephyrus\Database\DatabaseBroker;

class AuthHistoryBroker extends DatabaseBroker
{
    public function __construct()
    {
        parent::__construct();
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

        return AuthHistory::build($row);
    }

    public function getHistoryForUser(string $userId): array
    {
        $rows = $this->select(
            "SELECT * FROM auth_history WHERE user_id = ? ORDER BY auth_timestamp DESC",
            [$userId]
        );

        return array_map(fn($row) => AuthHistory::build($row), $rows);
    }
}
