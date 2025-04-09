<?php

namespace Models\src\Services\Utils;

class AvatarService extends BaseService
{
    private const array ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    private const string UPLOAD_FOLDER = '/uploads';

    public function upload(array $file): array
    {
        if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['error' => 'Échec de l’upload.'];
        }

        if (!is_uploaded_file($file['tmp_name'])) {
            return ['error' => 'Fichier non valide ou non sécurisé.'];
        }

        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            return ['error' => 'Extension de fichier non autorisée.'];
        }

        $filename = uniqid('avatar_', true) . '.' . $extension;
        $uploadDir = $_SERVER['DOCUMENT_ROOT'] . self::UPLOAD_FOLDER;

        if (!is_dir($uploadDir) && !mkdir($uploadDir, 0755, true) && !is_dir($uploadDir)) {
            return ['error' => 'Impossible de créer le dossier d’upload.'];
        }

        $uploadPath = $uploadDir . '/' . $filename;

        if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
            return ['error' => 'Impossible de sauvegarder le fichier.'];
        }

        return ['publicUrl' => self::UPLOAD_FOLDER . '/' . $filename];
    }
}
