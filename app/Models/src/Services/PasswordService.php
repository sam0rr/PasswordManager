<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Entities\UserPassword;
use Models\src\Services\Utils\BaseService;
use Models\src\Validators\PasswordValidator;
use Zephyrus\Application\Form;

class PasswordService extends BaseService
{
    protected PasswordBroker $passwordBroker;
    protected UserBroker $userBroker;
    protected EncryptionService $encryption;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->encryption = new EncryptionService();
        $this->passwordBroker = new PasswordBroker();
        $this->userBroker = new UserBroker();
    }

    public function getPasswords(Form $form, $isHtmx): array
    {
        try {
            PasswordValidator::assertPasswordVerification($form, $isHtmx);
            $user = $this->getVerifiedUser($form);

            $passwords = $this->passwordBroker->findAllByUser($user->id, $this->auth['user_key']);
            return $this->buildSuccessGetResponse($passwords);

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function getAllUserPasswords(Form $form): array
    {
        try {
            $user = $this->getVerifiedUser($form);

            $passwords = $this->passwordBroker->findAllByUser($user->id, $this->auth['user_key']);
            return $this->buildSuccessGetResponse($passwords);

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function addPassword(Form $form, bool $isHtmx): array
    {
        try {
            PasswordValidator::assertAdd($form, $this->passwordBroker, $this->auth['user_id'], $isHtmx);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "status" => 200
                ];
            }

            $data = $this->buildEncryptedPasswordData($form);
            $password = $this->passwordBroker->createPassword($data, $this->auth['user_key']);

            return $this->buildSuccessAddResponse($password);

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form, string $id, bool $isHtmx): array
    {
        try {
            $password = $this->validateAndGetPassword($id, $form);
            PasswordValidator::assertUpdate($form, $this->passwordBroker, $this->auth['user_id'], $password);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "status" => 200
                ];
            }

            $updates = $this->buildEncryptedUpdateData($form);
            if (!empty($updates)) {
                $this->passwordBroker->updatePassword($id, $updates);
            }

            $updatedPassword = $this->passwordBroker->findById($id, $this->auth['user_key']);
            return $this->buildSuccessGetResponse([$updatedPassword]);

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function deletePassword(Form $form, string $id, bool $isHtmx): array
    {
        try {
            PasswordValidator::assertPasswordVerification($form, $isHtmx);
            $this->validateAndGetPassword($id, $form);
            $this->getVerifiedUser($form);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "status" => 200
                ];
            }

            $this->passwordBroker->deletePassword($id);
            return ["status" => 200, "message" => "Mot de passe supprimé avec succès."];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePasswordsWithNewKey(string $userId, string $oldKey, string $newKey): void
    {
        $passwords = $this->passwordBroker->findAllByUser($userId, $oldKey);

        foreach ($passwords as $p) {
            $this->passwordBroker->updatePassword($p->id, [
                'description' => $this->encryption->encryptWithUserKey($p->description, $newKey),
                'description_hash' => $this->encryption->hash256($p->description),
                'email_from' => $this->encryption->encryptWithUserKey($p->email_from, $newKey),
                'note' => $this->encryption->encryptWithUserKey($p->note, $newKey),
                'password' => $this->encryption->encryptWithUserKey($p->password, $newKey)
            ]);
        }
    }

    // Helpers

    private function getVerifiedUser(Form $form): User
    {
        $submittedPassword = $form->getValue("password");
        $user = $this->getAuthenticatedUser($submittedPassword, $form);
        $this->verifyTempKey($submittedPassword, $user->salt, $form);
        return $user;
    }

    private function validateAndGetPassword(string $id, Form $form): UserPassword
    {
        $this->assertValidPasswordId($id, $form);
        return $this->getPassword($id, $form);
    }

    private function buildEncryptedPasswordData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $description = $form->getValue('description');
        $user = $this->userBroker->findById($this->auth['user_id'], $key);

        return [
            'user_id' => $this->auth['user_id'],
            'description' => $this->encryption->encryptWithUserKey($description, $key),
            'description_hash' => $this->encryption->hash256($description),
            'email_from' => $this->encryption->encryptWithUserKey($user->email, $key),
            'note' => $this->encryption->encryptWithUserKey($form->getValue('note'), $key),
            'password' => $this->encryption->encryptWithUserKey($form->getValue('password'), $key),
            'verified' => true
        ];
    }

    private function buildEncryptedUpdateData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $updates = [];

        foreach (['description', 'note', 'password'] as $field) {
            $value = $form->getValue($field);
            if (!empty($value)) {
                $updates[$field] = $this->encryption->encryptWithUserKey($value, $key);
                if ($field === 'description') {
                    $updates['description_hash'] = $this->encryption->hash256($value);
                }
            }
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
            "passwords" => array_map(fn($p) => $this->formatPassword($p), $passwords)
        ];
    }

    private function buildSuccessAddResponse(UserPassword $p): array
    {
        return [
            "status" => 201,
            "message" => "Mot de passe ajouté.",
            "password" => $this->formatPassword($p)
        ];
    }

    private function formatPassword(UserPassword $p): array
    {
        return [
            "id" => $p->id,
            "description" => $p->description,
            "description_hash" => $p->description_hash,
            "email_from" => $p->email_from,
            "note" => $p->note,
            "password" => $p->password,
            "last_use" => $p->last_use,
            "created_at" => $p->created_at,
            "updated_at" => $p->updated_at,
            "verified" => $p->verified
        ];
    }
}
