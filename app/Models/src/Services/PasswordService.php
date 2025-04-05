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

    public function updatePasswordsWithNewKey(string $userId, string $oldKey, string $newKey): void
    {
        $passwords = $this->passwordBroker->findAllByUser($userId, $oldKey);

        foreach ($passwords as $password) {
            $updates = [
                'description'        => $this->encryption->encryptWithUserKey($password->description, $newKey),
                'description_hash'   => $this->encryption->hash256($password->description),
                'note'               => $this->encryption->encryptWithUserKey($password->note, $newKey),
                'encrypted_password' => $this->encryption->encryptWithUserKey($password->encrypted_password, $newKey),
            ];

            $this->passwordBroker->updatePassword($password->id, $updates);
        }
    }

    // Helpers

    private function buildEncryptedPasswordData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $description = $form->getValue('description');

        return [
            'user_id'            => $this->auth['user_id'],
            'description'        => $this->encryption->encryptWithUserKey($description, $key),
            'description_hash'   => $this->encryption->hash256($description),
            'note'               => $this->encryption->encryptWithUserKey($form->getValue('note'), $key),
            'encrypted_password' => $this->encryption->encryptWithUserKey($form->getValue('password'), $key)
        ];
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
            "encrypted_password" => $p->encrypted_password,
            "last_use" => $p->last_use,
            "created_at" => $p->created_at,
            "updated_at" => $p->updated_at
        ];
    }
}
