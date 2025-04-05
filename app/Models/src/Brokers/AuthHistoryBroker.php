<?php

namespace Models\src\Brokers;

use Zephyrus\Database\DatabaseBroker;

class AuthHistoryBroker extends DatabaseBroker
{
    public function logAuthEvent(array $data): void
    {
        $this->query(
            "INSERT INTO auth_history (user_id, ip_address, user_agent, result, location)
             VALUES (?, ?, ?, ?, ?)",
            [
                $data['user_id'],
                $data['ip_address'],
                $data['user_agent'],
                $data['result'],
                $data['location']
            ]
        );
    }

    public function getHistoryForUser(string $userId): array
    {
        return $this->select(
            "SELECT * FROM auth_history WHERE user_id = ? ORDER BY auth_timestamp DESC",
            [$userId]
        );
    }

}
