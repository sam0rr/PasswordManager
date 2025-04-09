<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class UserValidator extends BaseValidator
{
    public static function assertUpdate(Form $form, UserBroker $broker, string $currentUserId): void
    {
        $form->field("first_name", [
            Rule::minLength(2, "Le prénom doit contenir au moins 2 caractères.")
        ])->optional();

        $form->field("last_name", [
            Rule::minLength(2, "Le nom doit contenir au moins 2 caractères.")
        ])->optional();

        $form->field("email", [
            Rule::email("Adresse courriel invalide.")
        ])->optional();

        $form->field("phone", [
            Rule::phone("Numéro de téléphone invalide.")
        ])->optional();

        $newEmail = $form->getValue("email");
        if (!empty($newEmail)) {
            $existingUser = $broker->findByEmail($newEmail);
            if ($existingUser && $existingUser->id !== $currentUserId) {
                $form->addError("email", "Cette adresse courriel est déjà utilisée.");
            }
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    public static function assertUpdatePassword(Form $form, bool $isHtmx): void
    {
        $oldPasswordField = $form->field("old", [
            Rule::required("L'ancien mot de passe est requis."),
            Rule::minLength(8, "L'ancien mot de passe est trop court.")
        ]);
        self::optionalIf($oldPasswordField, $isHtmx);

        $newPasswordField = $form->field("new", [
            Rule::required("Le nouveau mot de passe est requis."),
            Rule::minLength(8, "Le nouveau mot de passe doit contenir au moins 8 caractères.")
        ]);
        self::optionalIf($newPasswordField, $isHtmx);

        $old = $form->getValue("old");
        $new = $form->getValue("new");
        if (!empty($old) && !empty($new) && $old === $new) {
            $form->addError("new", "Le nouveau mot de passe doit être différent de l'ancien.");
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
