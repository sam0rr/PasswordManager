<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;

class UserService extends BaseService
{
    private UserBroker $userBroker;
    private array $auth;
    private EncryptionService $encryption;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->userBroker = new UserBroker();
        $this->encryption = new EncryptionService();
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

    public function updateUser(Form $form): array
    {
        try {
            UserValidator::assertUpdate($form, $this->userBroker, $this->auth['user_id']);

            $form->removeField('password');
            $updates = $this->buildEncryptedUpdateData($form);
            $this->userBroker->updateUser($this->auth['user_id'], $updates);
            $user = $this->getCurrentUserEntity();

            return $this->buildSuccessUpdateResponse($user);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form): array
    {
        try {
            UserValidator::assertUpdatePassword($form);

            $currentUser = $this->getCurrentUserEntity();
            $currentPassword = $form->getValue('old');
            $newPassword = $form->getValue('new');

            // Vérifie le mot de passe actuel
            if (!$this->encryption->verifyPassword($currentPassword, $currentUser->password_hash)) {
                $form->addError("old", "Mot de passe actuel invalide.");
                throw new FormException($form);
            }

            // Déchiffrer les données avec l’ancienne clé
            $oldKey = $this->auth['user_key'];
            $plainData = [
                'first_name' => $this->encryption->decryptWithUserKey($currentUser->first_name, $oldKey),
                'last_name' => $this->encryption->decryptWithUserKey($currentUser->last_name, $oldKey),
                'email' => $this->encryption->decryptWithUserKey($currentUser->email, $oldKey),
                'phone' => $this->encryption->decryptWithUserKey($currentUser->phone, $oldKey),
                'image_url' => $this->encryption->decryptWithUserKey($currentUser->image_url, $oldKey)
            ];

            // Générer nouvelle clé + salt
            $newSalt = $this->encryption->generateSalt();
            $newKey = $this->encryption->deriveUserKey($newPassword, $newSalt);
            $newHash = $this->encryption->hashPassword($newPassword);

            // Ré-encrypter les données
            $updated = [
                'first_name'    => $this->encryption->encryptWithUserKey($plainData['first_name'], $newKey),
                'last_name'     => $this->encryption->encryptWithUserKey($plainData['last_name'], $newKey),
                'email'         => $this->encryption->encryptWithUserKey($plainData['email'], $newKey),
                'phone'         => $this->encryption->encryptWithUserKey($plainData['phone'], $newKey),
                'image_url'     => $this->encryption->encryptWithUserKey($plainData['image_url'], $newKey),
                'email_hash'    => $this->encryption->hash256($plainData['email']),
                'password_hash' => $newHash,
                'salt'          => $newSalt
            ];

            // Dans le futur --> Ré-encrypter les mots de passes et les données associées

            $this->userBroker->updateUser($this->auth['user_id'], $updated);
            $this->encryption->storeUserContext($currentUser->id, $newKey); // Met à jour la session

            return [
                "status" => 200,
                "message" => "Mot de passe mis à jour avec succès."
            ];
        } catch (FormException $e) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

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

        if ($form->getValue('password')) {
            $data['password_hash'] = $this->encryption->hashPassword($form->getValue('password'));
        }

        return $data;
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
            "mfa_end" => $user->mfa_end,
            "created_at" => $user->created_at,
            "updated_at" => $user->updated_at
        ];
    }
}
