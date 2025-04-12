<?php

namespace Models\src\Services;

use Zephyrus\Network\HttpRequester;

//Code William T1willi merci
class SecurityService
{
    private static function calculatePasswordStrength(string $password): array
    {
        $length = strlen($password);
        $charset = 0;

        if (preg_match('/[a-z]/', $password)) $charset += 26;
        if (preg_match('/[A-Z]/', $password)) $charset += 26;
        if (preg_match('/[0-9]/', $password)) $charset += 10;
        if (preg_match('/[^a-zA-Z0-9]/', $password)) $charset += 32;

        $entropy = $length * ($charset > 0 ? log($charset, 2) : 0);

        if ($entropy >= 85) {
            $strength = 'Strong';
        } elseif ($entropy >= 75) {
            $strength = 'Medium';
        } else {
            $strength = 'Weak';
        }

        return [
            'strength' => $strength,
            'entropy' => round($entropy, 2)
        ];
    }

    public static function findBreachCount(string $password): int
    {
        $sha1Hash = strtoupper(sha1($password));
        $sha1Prefix = substr($sha1Hash, 0, 5);

        $httpRequester = new HttpRequester("GET", "https://api.pwnedpasswords.com/range/{$sha1Prefix}");
        $httpRequester->addHeader('Add-Padding', 'true');
        $httpRequester->addHeader('User-Agent', 'JoltSecure/1.0 (Password Manager Security Check)');

        usleep(1500000); // Respect API pacing

        $httpResponse = $httpRequester->execute();
        if ($httpResponse->getHttpCode() == 404) {
            return 0;
        }

        $breaches = self::formatBreachResponse($httpResponse->getResponse(), $sha1Prefix);
        return $breaches[$sha1Hash] ?? 0;
    }

    private static function formatBreachResponse(string $rawResponse, string $sha1Prefix): array
    {
        $input = trim($rawResponse);
        if (empty($input)) {
            return [];
        }

        $results = explode("\n", $input);
        $breaches = [];
        foreach ($results as $result) {
            $parts = explode(":", trim($result));
            if (count($parts) !== 2) {
                continue;
            }
            list($hashSuffix, $count) = $parts;
            $breaches[$sha1Prefix . $hashSuffix] = (int) $count;
        }

        return $breaches;
    }

    private function analyzePasswords(array $passwords): array
    {
        $results = [];
        foreach ($passwords as $pwd) {
            $analysis = self::calculatePasswordStrength($pwd->password);
            $results[] = [
                'description' => $pwd->description,
                'entropy' => $analysis['entropy'],
                'strength' => $analysis['strength']
            ];
        }
        return $results;
    }

    private function analyzeBreaches(array $passwords): array
    {
        $results = [];
        foreach ($passwords as $pwd) {
            $count = self::findBreachCount($pwd->password);
            $results[] = [
                'description' => $pwd->description,
                'breaches' => $count
            ];
        }
        return $results;
    }

    public static function analyzeSecurity(array $passwords): array
    {
        $service = new SecurityService();
        $basic = $service->analyzePasswords($passwords);
        $breaches = $service->analyzeBreaches($passwords);

        foreach ($basic as &$entry) {
            foreach ($breaches as $b) {
                if ($entry['description'] === $b['description']) {
                    $entry['breach_count'] = $b['breaches'];
                    break;
                }
            }
        }

        return $basic;
    }
}
