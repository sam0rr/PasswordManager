<?php

namespace Models\src\Services\Utils;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\UserPassword;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\PasswordService;
use Models\src\Services\SharingService;
use Models\src\Services\UserService;
use Models\src\Services\Utils\Encryption\EncryptionService;
use Models\src\Services\VerifyService;
use Zephyrus\Application\Form;

class BaseService
{
    protected array $auth;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
    }

    //SHARED BROKERS

    protected ?PasswordBroker $passwordBroker = null {
        get {
            return $this->passwordBroker ??= new PasswordBroker($this->encryption);
        }
    }
    protected ?UserBroker $userBroker = null {
        get {
            return $this->userBroker ??= new UserBroker($this->encryption);
        }
    }
    protected ?EncryptionService $encryption = null {
        get {
            return $this->encryption ??= new EncryptionService();
        }
    }

    //PUBLIC SERVICES I NEED TO ACCESS OFTEN (SO I CAN JUST CREATE 1 OBJECT -> SAVING MEMORY)

    public ?UserService $userService = null {
        get {
            return $this->userService ??= new UserService($this->auth);
        }
    }
    public ?PasswordService $passwordService = null {
        get {
            return $this->passwordService ??= new PasswordService($this->auth);
        }
    }
    public ?AuthHistoryService $history = null {
        get {
            return $this->history ??= new AuthHistoryService($this->auth);
        }
    }
    public ?SharingService $sharing = null {
        get {
            return $this->sharing ??= new SharingService($this->auth);
        }
    }
    public ?VerifyService $verify = null {
        get {
            return $this->verify ??= new VerifyService($this->auth);
        }
    }

    //Helpers

    public static function buildErrorResponse(Form $form, array $extra = []): array
    {
        return array_merge([
            'errors' => true,
            'form' => $form
        ], $extra);
    }

    protected function getPassword(string $passwordId, Form $form): UserPassword
    {
        $password = $this->passwordBroker->findById($passwordId, $this->auth['user_key']);

        if (!$password || $password->user_id !== $this->auth['user_id']) {
            $form->addError('global', "Password Not Found Or Unauthorized Access.");
            throw new FormException($form);
        }

        return $password;
    }

}