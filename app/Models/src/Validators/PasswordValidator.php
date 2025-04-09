<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Entities\UserPassword;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class PasswordValidator extends BaseValidator
{
    public static function assertAdd(Form $form, PasswordBroker $broker, string $userId): void
    {
        $form->field("description", [
            Rule::required("La description est requise."),
            Rule::minLength(2, "La description doit contenir au moins 2 caractères.")
        ]);

        $form->field("note", [
            Rule::required("La note est requise."),
            Rule::minLength(2, "La note doit contenir au moins 2 caractères.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe est requis.")
        ]);

        $form->verify();

        $desc = $form->getValue("description");
        if (!empty($desc) && $broker->descriptionExistsForUser($userId, $desc)) {
            $form->addError("description", "Une description identique existe déjà.");
        }

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    public static function assertPasswordVerification(Form $form): void
    {
        $form->field("password", [
            Rule::required("Le mot de passe est requis."),
            Rule::minLength(8, "Le mot de passe doit contenir au moins 8 caractères.")
        ]);

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    public static function assertUpdate(Form $form, PasswordBroker $broker, string $userId, UserPassword $currentPassword): void
    {
        $form->field("password", [
            Rule::minLength(8, "Le mot de passe doit contenir au moins 8 caractères.")
        ])->optional();

        $form->field("description", [
            Rule::minLength(2, "La description doit contenir au moins 2 caractères.")
        ])->optional();

        $form->field("note", [
            Rule::minLength(2, "La note doit contenir au moins 2 caractères.")
        ])->optional();

        $form->field("verified", [
            Rule::boolean("Le champ 'verified' doit être un booléen.")
        ])->optional();

        $newDescription = $form->getValue("description");
        if (!empty($newDescription) && $broker->descriptionExistsForUser($userId, $newDescription)
            && $newDescription !== $currentPassword->description) {
            $form->addError("description", "Cette description est déjà utilisée.");
        }

        $newPassword = $form->getValue("password");
        if (!empty($newPassword) && $newPassword === $currentPassword->password) {
            $form->addError("password", "Le nouveau mot de passe doit être différent de l'ancien.");
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
