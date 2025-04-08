<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\UserPassword;
use Models\src\Validators\PasswordValidator;
use Zephyrus\Application\Form;

class PasswordService extends BaseService
{
    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->passwordBroker = new PasswordBroker();
        $this->userBroker = new UserBroker();
        $this->encryption = new EncryptionService();
    }

    public function getPasswords(Form $form): array
    {
        try {
            PasswordValidator::assertPasswordVerification($form);

            $submittedPassword = $form->getValue("password");
            $user = $this->getAuthenticatedUser($submittedPassword, $form);
            $this->verifyTempKey($submittedPassword, $user->salt, $form);

            $passwords = $this->passwordBroker->findAllByUser($user->id, $this->auth['user_key']);

            return $this->buildSuccessGetResponse($passwords);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function addPassword(Form $form): array
    {
        try {
            PasswordValidator::assertAdd($form, $this->passwordBroker, $this->auth['user_id']);

            $data = $this->buildEncryptedPasswordData($form);
            $password = $this->passwordBroker->createPassword($data, $this->auth['user_key']);

            return $this->buildSuccessAddResponse($password);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form, string $passwordId): array
    {
        try {
            $this->assertValidPasswordId($passwordId, $form);

            $password = $this->getPassword($passwordId, $form);

            PasswordValidator::assertUpdate($form, $this->passwordBroker, $this->auth['user_id'], $password);

            $updates = $this->buildEncryptedUpdateData($form);

            if (!empty($updates)) {
                $this->passwordBroker->updatePassword($passwordId, $updates);
            }

            $updatedPassword = $this->passwordBroker->findById($passwordId, $this->auth['user_key']);

            return $this->buildPasswordResponse($updatedPassword);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function deletePassword(Form $form, string $passwordId): array
    {
        try {
            $this->assertValidPasswordId($passwordId, $form);

            PasswordValidator::assertPasswordVerification($form);

            $submittedPassword = $form->getValue("password");
            $user = $this->getAuthenticatedUser($submittedPassword, $form);
            $this->verifyTempKey($submittedPassword, $user->salt, $form);

            $this->getPassword($passwordId, $form);

            $this->passwordBroker->deletePassword($passwordId);

            return [
                "status" => 200,
                "message" => "Mot de passe supprimé avec succès."
            ];
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function getPassword(string $passwordId, Form $form): UserPassword
    {
        $password = $this->passwordBroker->findById($passwordId, $this->auth['user_key']);

        if (!$password || $password->user_id !== $this->auth['user_id']) {
            $form->addError('global', "Mot de passe introuvable ou non autorisé.");
            throw new FormException($form);
        }

        return $password;
    }

    public function updatePasswordsWithNewKey(string $userId, string $oldKey, string $newKey): void
    {
        $passwords = $this->passwordBroker->findAllByUser($userId, $oldKey);

        foreach ($passwords as $password) {
            $updates = [
                'description'        => $this->encryption->encryptWithUserKey($password->description, $newKey),
                'description_hash'   => $this->encryption->hash256($password->description),
                'note'               => $this->encryption->encryptWithUserKey($password->note, $newKey),
                'password'           => $this->encryption->encryptWithUserKey($password->password, $newKey),
            ];

            $this->passwordBroker->updatePassword($password->id, $updates);
        }
    }

    private function buildEncryptedPasswordData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $description = $form->getValue('description');

        return [
            'user_id'            => $this->auth['user_id'],
            'description'        => $this->encryption->encryptWithUserKey($description, $key),
            'description_hash'   => $this->encryption->hash256($description),
            'note'               => $this->encryption->encryptWithUserKey($form->getValue('note'), $key),
            'password'           => $this->encryption->encryptWithUserKey($form->getValue('password'), $key),
            'verified'           => true
        ];
    }

    private function buildEncryptedUpdateData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $updates = [];

        $description = $form->getValue('description');
        if (!empty($description)) {
            $updates['description'] = $this->encryption->encryptWithUserKey($description, $key);
            $updates['description_hash'] = $this->encryption->hash256($description);
        }

        $note = $form->getValue('note');
        if (!empty($note)) {
            $updates['note'] = $this->encryption->encryptWithUserKey($note, $key);
        }

        $password = $form->getValue('password');
        if (!empty($password)) {
            $updates['password'] = $this->encryption->encryptWithUserKey($password, $key);
        }

        if (!is_null($form->getValue('verified'))) {
            $updates['verified'] = filter_var($form->getValue('verified'), FILTER_VALIDATE_BOOLEAN);
        }

        return $updates;
    }

    private function buildSuccessGetResponse(array $passwords): array
    {
        return [
            "status" => 200,
            "passwords" => array_map(fn(UserPassword $p) => $this->buildPasswordResponse($p), $passwords)
        ];
    }

    private function buildSuccessAddResponse(UserPassword $password): array
    {
        return [
            "status" => 201,
            "message" => "Mot de passe ajouté.",
            "password" => $this->buildPasswordResponse($password)
        ];
    }

    private function buildPasswordResponse(UserPassword $p): array
    {
        return [
            "id" => $p->id,
            "description" => $p->description,
            "description_hash" => $p->description_hash,
            "note" => $p->note,
            "password" => $p->password,
            "last_use" => $p->last_use,
            "created_at" => $p->created_at,
            "updated_at" => $p->updated_at,
            "verified" => $p->verified
        ];
    }

}
