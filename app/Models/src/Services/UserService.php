<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Services\Utils\AvatarService;
use Models\src\Services\Utils\BaseService;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;

class UserService extends BaseService
{
    protected PasswordService $passwordService;
    protected UserBroker $userBroker;
    protected EncryptionService $encryption;
    protected SharingService $sharing;
    protected AvatarService $avatar;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->userBroker = new UserBroker();
        $this->encryption = new EncryptionService();
        $this->passwordService = new PasswordService($auth);
        $this->sharing = new SharingService($auth);
        $this->avatar = new AvatarService();
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
                    "form" => $form,
                    "status" => 200
                ];
            }

            $form->removeField('password');

            $updates = $this->buildEncryptedUpdateData($form);
            $this->userBroker->updateUser($this->auth['user_id'], $updates);
            $user = $this->getCurrentUserEntity();

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
            'success' => true,
            'form' => $form,
            'user' => $this->getCurrentUserEntity()
        ];
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
                    "form" => $form,
                    "status" => 200
                ];
            }

            $this->sharing->acceptPendingShares();
            $user = $this->rotateUserKey($currentUser, $newPassword);

            return ["form" => $form, "user" => $user];
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function updateUserContext(string $userId, string $userKey): void
    {
        $this->encryption->storeUserContext($userId, $userKey);
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
                    $data['email_hash'] = $this->encryption->hash256($value);
                }
            }
        }

        return $data;
    }

    private function rotateUserKey(User $user, string $newPassword): User
    {
        // Étape 1 : Génération des nouvelles données encryptées
        $updated = $this->buildEncryptedDataWithNewPassword($user, $newPassword);
        $newUserKey = $updated['user_key'];
        unset($updated['user_key']);
        $oldUserKey = $this->auth['user_key'];

        // Étape 2 : Mettre à jour l'utilisateur
        $this->userBroker->updateUser($user->id, $updated);

        // Étape 3 : Mettre à jour les données dépendantes (passwords)
        $this->passwordService->updatePasswordsWithNewKey($user->id, $oldUserKey, $newUserKey);

        // Étape 4 : Mettre à jour le contexte
        $this->updateUserContext($user->id, $newUserKey);

        // Étape 5 : Retourner l’utilisateur mis à jour
        return $this->userBroker->findById($user->id, $newUserKey);
    }

    private function buildEncryptedDataWithNewPassword(User $user, string $newPassword): array
    {
        $newSalt = $this->encryption->generateSalt();
        $newKey = $this->encryption->deriveUserKey($newPassword, $newSalt);
        $newHash = $this->encryption->hashPassword($newPassword);
        $newPublicKey = $this->encryption->generatePublicKey($newKey);

        return [
            'first_name'    => $this->encryption->encryptWithUserKey($user->first_name, $newKey),
            'last_name'     => $this->encryption->encryptWithUserKey($user->last_name, $newKey),
            'email'         => $this->encryption->encryptWithUserKey($user->email, $newKey),
            'phone'         => $this->encryption->encryptWithUserKey($user->phone, $newKey),
            'image_url'     => $this->encryption->encryptWithUserKey($user->image_url, $newKey),
            'email_hash'    => $this->encryption->hash256($user->email),
            'password_hash' => $newHash,
            'salt'          => $newSalt,
            'public_key'    => $newPublicKey,
            'user_key'      => $newKey
        ];
    }

}