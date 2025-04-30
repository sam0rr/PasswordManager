<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Entities\UserPassword;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

final class PasswordValidator extends BaseValidator
{
    public static function assertAdd(Form $form, PasswordBroker $broker, string $userId, bool $isHtmx): void
    {
        $descField = $form->field("description", [
            Rule::required("La description est requise."),
            Rule::minLength(2, "La description doit contenir au moins 2 caractères."),
            Rule::maxLength(25, "La description doit contenir au maximum 25 caractères.")
        ]);
        self::optionalIf($descField, $isHtmx);

        $noteField = $form->field("note", [
            Rule::required("La note est requise."),
            Rule::minLength(2, "La note doit contenir au moins 2 caractères."),
            Rule::maxLength(50, "La description doit contenir au maximum 50 caractères.")
        ]);
        self::optionalIf($noteField, $isHtmx);

        $passwordField = $form->field("password", [
            Rule::required("Le mot de passe est requis."),
            Rule::minLength(2, "Le mot de passe doit contenir au moins 2 caractères.")
        ]);
        self::optionalIf($passwordField, $isHtmx);

        $form->verify();

        $desc = $form->getValue("description");
        if (!empty($desc) && $broker->descriptionExistsForUser($userId, $desc)) {
            $form->addError("description", "Une description identique existe déjà.");
        }

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    public static function assertUpdate(Form $form, PasswordBroker $broker, string $userId, UserPassword $currentPassword, $userKey): void
    {
        $form->field("password", [
            Rule::minLength(2, "Le mot de passe doit contenir au moins 2 caractères.")
        ])->optional();

        $form->field("description", [
            Rule::minLength(2, "La description doit contenir au moins 2 caractères."),
            Rule::maxLength(25, "La description doit contenir au maximum 25 caractères.")
        ])->optional();

        $form->field("note", [
            Rule::minLength(2, "La note doit contenir au moins 2 caractères."),
            Rule::maxLength(50, "La description doit contenir au maximum 50 caractères.")
        ])->optional();

        $newDescription = $form->getValue("description");
        if (!empty($newDescription)) {
            $existing = $broker->findByDescriptionForUser($userId, $newDescription, $userKey);
            if ($existing && $existing->id !== $currentPassword->id) {
                $form->addError("description", "Cette description est déjà utilisée.");
            }
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

}
