<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Entities\UserPassword;
use Models\src\Validators\PasswordValidator;
use Zephyrus\Application\Form;

class PasswordService extends BaseService
{
    private PasswordBroker $passwordBroker;
    private array $auth;
    private EncryptionService $encryption;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->passwordBroker = new PasswordBroker();
        $this->encryption = new EncryptionService();
    }

    public function getPasswords(): array
    {
        $passwords = $this->passwordBroker->findAllByUser($this->auth['user_id']);
        return array_map(fn(UserPassword $p) => $this->buildPasswordResponse($p), $passwords);
    }

    public function addPassword(Form $form): array
    {
        try {
            PasswordValidator::assertAdd($form, $this->passwordBroker, $this->auth['user_id']);

            $data = $this->buildEncryptedPasswordData($form);
            $password = $this->passwordBroker->createPassword($data);

            return $this->buildSuccessAddResponse($password);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
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
            "desccription_hash" => $p->description_hash,
            "note" => $p->note,
            "encrypted_password" => $p->encrypted_password,
            "last_use" => $p->last_use,
            "created_at" => $p->created_at,
            "updated_at" => $p->updated_at
        ];
    }
}
