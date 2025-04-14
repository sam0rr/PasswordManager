<?php

namespace Models\src\Services\Utils;

use Zephyrus\Network\HttpRequester;

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

        return [
            'strength' => $entropy >= 85 ? 'Strong' : ($entropy >= 75 ? 'Medium' : 'Weak'),
            'entropy' => round($entropy, 2)
        ];
    }

    public static function findBreachCount(string $password): int
    {
        $sha1Hash = strtoupper(sha1($password));
        $sha1Prefix = substr($sha1Hash, 0, 5);

        $httpRequester = new HttpRequester("GET", "https://api.pwnedpasswords.com/range/{$sha1Prefix}");
        $httpRequester->addHeader('Add-Padding', 'true');
        $httpRequester->addHeader('User-Agent', 'JoltSecure/1.0');

        usleep(1500000);

        $response = $httpRequester->execute();
        if ($response->getHttpCode() == 404) {
            return 0;
        }

        $breaches = self::formatBreachResponse($response->getResponse(), $sha1Prefix);
        return $breaches[$sha1Hash] ?? 0;
    }

    private static function formatBreachResponse(string $rawResponse, string $sha1Prefix): array
    {
        $lines = explode("\n", trim($rawResponse));
        $map = [];

        foreach ($lines as $line) {
            [$hashSuffix, $count] = array_pad(explode(":", trim($line)), 2, null);
            if ($hashSuffix && is_numeric($count)) {
                $map[$sha1Prefix . $hashSuffix] = (int) $count;
            }
        }

        return $map;
    }

    private function analyzePasswords(array $passwords): array
    {
        return array_map(fn($pwd) => [
            'id' => $pwd->id,
            'description' => $pwd->description,
            'note' => $pwd->note ?? null,
            'entropy' => self::calculatePasswordStrength($pwd->password)['entropy'],
            'strength' => self::calculatePasswordStrength($pwd->password)['strength']
        ], $passwords);
    }

    private function analyzeBreaches(array $passwords): array
    {
        $results = [];
        foreach ($passwords as $pwd) {
            $results[$pwd->id] = self::findBreachCount($pwd->password);
        }
        return $results;
    }

    public static function analyzeSecurity(array $passwords): array
    {
        $service = new self();
        $analysis = $service->analyzePasswords($passwords);
        $breaches = $service->analyzeBreaches($passwords);

        foreach ($analysis as &$entry) {
            $entry['breach_count'] = $breaches[$entry['id']] ?? 0;
        }

        return $analysis;
    }

    public static function analyzeIfChanged(array $passwords, array $previousMap, array $existingAnalysis = []): array
    {
        $newMap = self::generateFingerprintMap($passwords);
        $passwordMap = [];

        foreach ($passwords as $pwd) {
            $passwordMap[$pwd->id] = $pwd;
        }

        $toAnalyze = [];
        foreach ($newMap as $id => $hash) {
            if (!isset($previousMap[$id]) || $previousMap[$id] !== $hash) {
                $toAnalyze[] = $passwordMap[$id];
            }
        }

        if (empty($toAnalyze)) {
            return [
                'analysis' => $existingAnalysis,
                'fingerprintMap' => $previousMap
            ];
        }

        $newAnalysis = self::analyzeSecurity($toAnalyze);
        $merged = self::mergeAnalysis($existingAnalysis, $newAnalysis);

        return [
            'analysis' => $merged,
            'fingerprintMap' => $newMap
        ];
    }

    public static function mergeAnalysis(array $existing, array $new): array
    {
        $map = [];
        foreach ($existing as $entry) {
            $map[$entry['id']] = $entry;
        }
        foreach ($new as $entry) {
            $map[$entry['id']] = $entry;
        }
        return array_values($map);
    }

    public static function generateFingerprintMap(array $passwords): array
    {
        return array_reduce($passwords, function ($map, $pwd) {
            $map[$pwd->id] = md5($pwd->description . '::' . ($pwd->note ?? '') . '::' . $pwd->password);
            return $map;
        }, []);
    }

    public static function filterOutPasswordFromAnalysis(string $passwordId, array $existingAnalysis, array $existingFingerprintMap): array
    {
        $filteredAnalysis = array_filter($existingAnalysis, fn($entry) => $entry['id'] !== $passwordId);
        unset($existingFingerprintMap[$passwordId]);

        return [
            'analysis' => array_values($filteredAnalysis),
            'fingerprintMap' => $existingFingerprintMap
        ];
    }

}
