<?php

namespace Models\src\Services\Utils;

class AvatarService extends BaseService
{
    private const array ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    private const string UPLOAD_FOLDER = '/uploads';
    private const string TEMP_FOLDER = '/uploads/temp';

    public function uploadTemp(array $file): array
    {
        return $this->processUpload($file, self::TEMP_FOLDER);
    }

    public function upload(array $file): array
    {
        return $this->processUpload($file, self::UPLOAD_FOLDER);
    }

    public function moveFromTemp(string $tempFilePath): array
    {
        if (!str_starts_with($tempFilePath, self::TEMP_FOLDER)) {
            return ['error' => 'Chemin de fichier invalide.'];
        }

        $tempFullPath = $_SERVER['DOCUMENT_ROOT'] . $tempFilePath;

        if (!file_exists($tempFullPath)) {
            return ['error' => 'Fichier temporaire introuvable.'];
        }

        $extension = pathinfo($tempFullPath, PATHINFO_EXTENSION);
        $filename = uniqid('avatar_', true) . '.' . $extension;
        $finalUrl = self::UPLOAD_FOLDER . '/' . $filename;
        $finalPath = $_SERVER['DOCUMENT_ROOT'] . $finalUrl;

        if (!copy($tempFullPath, $finalPath)) {
            return ['error' => 'Impossible de déplacer le fichier.'];
        }

        unlink($tempFullPath);

        return ['publicUrl' => $finalUrl];
    }

    private function processUpload(array $file, string $targetFolder): array
    {
        if (empty($file) || !isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['error' => 'Échec de l\'upload.'];
        }

        if (!is_uploaded_file($file['tmp_name'])) {
            return ['error' => 'Fichier non valide ou non sécurisé.'];
        }

        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            return ['error' => 'Extension de fichier non autorisée.'];
        }

        $filename = uniqid('avatar_', true) . '.' . $extension;
        $uploadDir = $_SERVER['DOCUMENT_ROOT'] . $targetFolder;

        if (!is_dir($uploadDir)) {
            if (!mkdir($uploadDir, 0755, true)) {
                return ['error' => 'Impossible de créer le dossier d\'upload.'];
            }
        }

        $uploadPath = $uploadDir . '/' . $filename;

        if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
            return ['error' => 'Impossible de sauvegarder le fichier.'];
        }

        return ['publicUrl' => $targetFolder . '/' . $filename];
    }

    public function cleanupTempFiles(int $maxAgeMinutes = 60): void
    {
        $tempDir = $_SERVER['DOCUMENT_ROOT'] . self::TEMP_FOLDER;
        if (!is_dir($tempDir)) {
            return;
        }

        $files = glob($tempDir . '/*');
        if ($files === false) {
            return;
        }

        $now = time();

        foreach ($files as $file) {
            if (is_file($file) && ($now - filemtime($file) > $maxAgeMinutes * 60)) {
                unlink($file);
            }
        }
    }
}