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
            Rule::required("Description Is Required."),
            Rule::minLength(2, "Description Must Be At Least 2 Characters."),
            Rule::maxLength(25, "Description Must Be No More Than 25 Characters.")
        ]);
        self::optionalIf($descField, $isHtmx);

        $noteField = $form->field("note", [
            Rule::required("Note Is Required."),
            Rule::minLength(2, "Note Must Be At Least 2 Characters."),
            Rule::maxLength(50, "Note Must Be No More Than 50 Characters.")
        ]);
        self::optionalIf($noteField, $isHtmx);

        $passwordField = $form->field("password", [
            Rule::required("Password Is Required."),
            Rule::minLength(2, "Password Must Be At Least 2 Characters.")
        ]);
        self::optionalIf($passwordField, $isHtmx);

        $form->verify();

        $desc = $form->getValue("description");
        if (!empty($desc) && $broker->descriptionExistsForUser($userId, $desc)) {
            $form->addError("description", "A Password With This Description Already Exists.");
        }

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

    public static function assertUpdate(Form $form, PasswordBroker $broker, string $userId, UserPassword $currentPassword, $userKey): void
    {
        $form->field("password", [
            Rule::minLength(2, "Password Must Be At Least 2 Characters.")
        ])->optional();

        $form->field("description", [
            Rule::minLength(2, "Description Must Be At Least 2 Characters."),
            Rule::maxLength(25, "Description Must Be No More Than 25 Characters.")
        ])->optional();

        $form->field("note", [
            Rule::minLength(2, "Note Must Be At Least 2 Characters."),
            Rule::maxLength(50, "Note Must Be No More Than 50 Characters.")
        ])->optional();

        $newDescription = $form->getValue("description");
        if (!empty($newDescription)) {
            $existing = $broker->findByDescriptionForUser($userId, $newDescription, $userKey);
            if ($existing && $existing->id !== $currentPassword->id) {
                $form->addError("description", "This Description Is Already In Use.");
            }
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

}
