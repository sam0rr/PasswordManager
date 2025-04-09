<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;

class UserService extends BaseService
{
    protected PasswordService $passwordService;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->userBroker = new UserBroker();
        $this->encryption = new EncryptionService();
        $this->passwordService = new PasswordService($auth);
        $this->sharing = new SharingService($auth);
    }

    public function getCurrentUserEntity(): ?User
    {
        return $this->userBroker->findById($this->auth['user_id'], $this->auth['user_key']);
    }

    public function getCurrentUser(): ?array
    {
        $user = $this->getCurrentUserEntity();
        return $user ? $this->buildUserResponse($user) : null;
    }

    public function updateUser(Form $form, $isHtmx): array
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

            return $this->buildSuccessUpdateResponse($user);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form, $isHtmx): array
    {
        try {
            UserValidator::assertUpdatePassword($form, $isHtmx);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "status" => 200
                ];
            }

            $currentUser = $this->getCurrentUserEntity();
            $currentPassword = $form->getValue('old');
            $newPassword = $form->getValue('new');

            if (!$this->encryption->verifyPassword($currentPassword, $currentUser->password_hash)) {
                $form->addError("old", "Mot de passe actuel invalide.");
                throw new FormException($form);
            }

            //Accepter avant la rotation des clées
            $this->sharing->acceptPendingShares();

            $user = $this->rotateUserKey($currentUser, $newPassword);

            return $this->buildSuccessUpdateResponse($user);
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

    private function buildEncryptedUpdateData(Form $form): array
    {
        $data = [];
        $key = $this->auth['user_key'];

        foreach (['first_name', 'last_name', 'email', 'phone', 'image_url'] as $field) {
            if ($form->getValue($field)) {
                $data[$field] = $this->encryption->encryptWithUserKey($form->getValue($field), $key);
                if ($field === 'email') {
                    $data['email_hash'] = $this->encryption->hash256($form->getValue('email'));
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

    private function buildSuccessUpdateResponse(User $user): array
    {
        return [
            "status" => 200,
            "message" => "Profil mis à jour avec succès.",
            "user" => $this->buildUserResponse($user)
        ];
    }

    private function buildUserResponse(User $user): array
    {
        return [
            "id" => $user->id,
            "email" => $user->email,
            "first_name" => $user->first_name,
            "last_name" => $user->last_name,
            "phone" => $user->phone,
            "image_url" => $user->image_url,
            "mfa" => $user->mfa,
            "salt" => $user->salt,
            "public_key" => $user->public_key,
            "mfa_end" => $user->mfa_end,
            "created_at" => $user->created_at,
            "updated_at" => $user->updated_at
        ];
    }
}