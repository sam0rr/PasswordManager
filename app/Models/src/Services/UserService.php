<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Entities\User;
use Models\src\Services\Utils\AvatarService;
use Models\src\Services\Utils\BaseService;
use Models\src\Services\Utils\SessionContextService;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;

final class UserService extends BaseService
{
    private ?AvatarService $avatar = null {
        get {
            return $this->avatar ??= new AvatarService($this->auth);
        }
    }

    public function getCurrentUserEntity(): ?User
    {
        return $this->userBroker->findById($this->auth['user_id'], $this->auth['user_key']);
    }

    public function updateUser(Form $form, bool $isHtmx): array
    {
        try {
            UserValidator::assertUpdate($form, $this->userBroker, $this->auth['user_id']);

            if ($isHtmx) {
                return [
                    "form" => $form
                ];
            }

            $form->removeField('password');

            $updates = $this->buildEncryptedUpdateData($form);
            $this->userBroker->updateUser($this->auth['user_id'], $updates);

            return [
                'form' => $form,
                'user' => $this->getCurrentUserEntity()
            ];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form, bool $isHtmx): array
    {
        try {
            UserValidator::assertUpdatePassword($form, $isHtmx);

            $currentUser = $this->getCurrentUserEntity();
            $currentPassword = $form->getValue('old');
            $newPassword = $form->getValue('new');

            if (!empty($currentPassword) && !$this->encryption->verifyPassword($currentPassword, $currentUser->password_hash)) {
                $form->addError("old", "Mot de passe actuel invalide.");
                throw new FormException($form);
            }

            if ($isHtmx) {
                return [
                    'form' => $form
                ];
            }

            $this->sharing->acceptPendingShares();
            $user = $this->rotateUserKey($currentUser, $newPassword);

            return ["form" => $form, "user" => $user];
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updateAvatar(Form $form, ?array $avatarFile): array
    {
        if (empty($avatarFile) || $avatarFile['error'] !== UPLOAD_ERR_OK) {
            $form->addError('avatar', "Veuillez sélectionner une image valide à uploader.");
            return $this->buildErrorResponse($form);
        }

        $this->processAvatarUpload($form, $avatarFile);

        if ($form->hasError()) {
            return $this->buildErrorResponse($form);
        }

        $imageUrl = $form->getValue('image_url');

        if (empty($imageUrl)) {
            $form->addError('avatar', "Une erreur s'est produite lors de l'upload de l'image.");
            return $this->buildErrorResponse($form);
        }

        $encryptedImageUrl = $this->encryption->encryptWithUserKey(
            $imageUrl,
            $this->auth['user_key']
        );

        $this->userBroker->updateUser($this->auth['user_id'], ['image_url' => $encryptedImageUrl]);

        return [
            'form' => $form,
            'user' => $this->getCurrentUserEntity()
        ];
    }

    // Helpers

    private function updateUserContext(string $userId, string $userKey): void
    {
        SessionContextService::store($userId, $userKey);
        $this->auth['user_key'] = $userKey;
    }

    private function processAvatarUpload(Form $form, ?array $avatarFile): void
    {
        if (!empty($avatarFile) && $avatarFile['error'] === UPLOAD_ERR_OK) {
            $result = $this->handleAvatarUpload($avatarFile);

            if (isset($result['publicUrl'])) {
                $form->addField('image_url', $result['publicUrl']);
            } elseif (isset($result['error'])) {
                $form->addError('avatar', $result['error']);
                throw new FormException($form);
            }
        }
    }

    private function handleAvatarUpload(array $avatarFile): array
    {
        return $this->avatar->upload($avatarFile);
    }

    private function buildEncryptedUpdateData(Form $form): array
    {
        $data = [];
        $key = $this->auth['user_key'];

        foreach (['first_name', 'last_name', 'email', 'phone', 'image_url'] as $field) {
            $value = $form->getValue($field);
            if (!empty($value)) {
                $data[$field] = $this->encryption->encryptWithUserKey($value, $key);
                if ($field === 'email') {
                    $data['email_hash'] = $this->encryption->hash256(strtolower($value));
                }
            }
        }

        return $data;
    }

    private function rotateUserKey(User $user, string $newPassword): User
    {
        $oldKey     = $this->auth['user_key'];
        $newSalt    = $this->encryption->generateSalt();
        $newKey     = $this->encryption->deriveUserKey($newPassword, $newSalt);
        $newHash    = $this->encryption->hashPassword($newPassword);
        $newPubKey  = $this->encryption->generatePublicKey($newKey);

        $updates = $this->getUpdates($user, $oldKey, $newKey, $newHash, $newSalt, $newPubKey);

        $this->userBroker->updateUser($user->id, $updates);

        // rotate passwords & OTPs
        $this->passwordService->updatePasswordsWithNewKey($user->id, $oldKey, $newKey);
        $this->verify->updateOtpWithNewKey      ($user->id, $oldKey, $newKey);

        $this->updateUserContext($user->id, $newKey);

        return $this->userBroker->findById($user->id, $newKey);
    }

    public function getUpdates(User $user, mixed $oldKey, string $newKey, string $newHash, string $newSalt, string $newPubKey): array
    {
        $raw = $this->userBroker->findRawEncryptedById($user->id);
        $fields = ['first_name', 'last_name', 'email', 'phone', 'image_url'];
        $updates = [];
        foreach ($fields as $f) {
            $updates[$f] = $this->encryption
                ->rewrapEnvelope($raw->$f, $oldKey, $newKey);
        }
        $updates['email_hash'] = $raw->email_hash;

        $updates['password_hash'] = $newHash;
        $updates['salt'] = $newSalt;
        $updates['public_key'] = $newPubKey;

        return $updates;
    }

}
