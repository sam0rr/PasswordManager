<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

final class UserValidator extends BaseValidator
{
    public static function assertUpdate(Form $form, UserBroker $broker, string $currentUserId): void
    {
        $form->field("first_name", [
            Rule::minLength(2, "First Name Must Be At Least 2 Characters.")
        ])->optional();

        $form->field("last_name", [
            Rule::minLength(2, "Last Name Must Be At Least 2 Characters.")
        ])->optional();

        $form->field("email", [
            Rule::email("Email Address Is Invalid.")
        ])->optional();

        $form->field("phone", [
            Rule::phone("Phone Number Is Invalid.")
        ])->optional();

        $newEmail = $form->getValue("email");
        if (!empty($newEmail)) {
            $existingUser = $broker->findByEmail($newEmail);
            if ($existingUser && $existingUser->id !== $currentUserId) {
                $form->addError("email", "This Email Address Is Already In Use.");
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
            Rule::required("Current Password Is Required."),
            Rule::minLength(8, "Current Password Is Too Short."),
            Rule::passwordCompliant("The Current Password Is Not Password Compliant.")
        ]);
        self::optionalIf($oldPasswordField, $isHtmx);

        $newPasswordField = $form->field("new", [
            Rule::required("New Password Is Required."),
            Rule::minLength(8, "New Password Must Be At Least 8 Characters."),
            Rule::passwordCompliant("The New Password Is Not Password Compliant.")
        ]);
        self::optionalIf($newPasswordField, $isHtmx);

        $old = $form->getValue("old");
        $new = $form->getValue("new");
        if (!empty($old) && !empty($new) && $old === $new) {
            $form->addError("new", "New Password Must Be Different From The Current One.");
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }

}
