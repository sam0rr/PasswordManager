<?php

namespace Models\src\Services\Utils;

final class AvatarService extends BaseService
{
    private const array ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    private const string UPLOAD_FOLDER = '/uploads';

    public function upload(array $file): array
    {
        return $this->processUpload($file);
    }

    private function processUpload(array $file): array
    {
        if (empty($file) || !isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['error' => 'Upload failed.'];
        }

        if (!is_uploaded_file($file['tmp_name'])) {
            return ['error' => 'Invalid or unsafe file.'];
        }

        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            return ['error' => 'File extension not allowed.'];
        }

        $filename = uniqid('avatar_', true) . '.' . $extension;
        $uploadDir = $_SERVER['DOCUMENT_ROOT'] . self::UPLOAD_FOLDER;

        if (!is_dir($uploadDir)) {
            if (!mkdir($uploadDir, 0755, true)) {
                return ['error' => 'Failed to create upload directory.'];
            }
        }

        $uploadPath = $uploadDir . '/' . $filename;

        if (!move_uploaded_file($file['tmp_name'], $uploadPath)) {
            return ['error' => 'Failed to save uploaded file.'];
        }

        return ['publicUrl' => self::UPLOAD_FOLDER . '/' . $filename];
    }

}
