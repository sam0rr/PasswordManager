# PASSWORD MANAGER

## Structure

### Controllers

- `UserController`: Gestion des inscriptions, authentifications, et des profils utilisateurs.
- `AuthenticationController`: Gestion des méthodes MFA (activation, vérification).
- `PasswordController`: Ajout, modification, suppression et récupération des mots de passe utilisateur.
- `SharingController`: Gestion du partage des mots de passe entre utilisateurs.

### Services

- `UserService`: Gestion des utilisateurs (création, mise à jour, vérification email).
- `AuthenticationService`: Gestion de la logique d'authentification multi-facteurs et chiffrement des clés MFA.
- `EncryptionService`: Chiffrement et déchiffrement des données sensibles (mots de passe, clés MFA).
- `PasswordService`: Gestion sécurisée des mots de passe (création, update, suppression).
- `SharingService`: Logique du partage sécurisé des passwords.

### Validators

- `UserValidator`: Validation des données utilisateur (email, mot de passe, informations personnelles).
- `AuthenticationValidator`: Validation des méthodes MFA et des jetons.
- `PasswordValidator`: Validation des données de gestion des mots de passe.
- `SharingValidator`: Validation des demandes de partage de mots de passe.

### Brokers

- `UserBroker`: Interaction avec la table utilisateurs.
- `AuthenticationBroker`: Interaction avec la table d'authentification MFA.
- `PasswordBroker`: Interaction avec la table des mots de passe.
- `SharingBroker`: Interaction avec la table de partage sécurisé des mots de passe.

### Models

- `UserModel`: Représentation des données utilisateur.
- `AuthenticationModel`: Représentation des configurations MFA.
- `PasswordModel`: Représentation des informations des mots de passe enregistrés.
- `SharingModel`: Représentation du partage de mots de passe entre utilisateurs.

## Sécurité et chiffrement

Toutes les données sensibles sont chiffrées avant stockage. Les mots de passe utilisateur sont hashés automatiquement avec `password_hash()` de PHP, avec son sel interne.

### Gestion des clés d'encryption utilisateur

Chaque utilisateur dispose d'une clé d'encryption personnelle utilisée pour chiffrer ses mots de passe enregistrés. Cette approche garantit qu'un compromis de la base de données ne permet pas l'accès aux mots de passe stockés.

#### Utilisation du sel (salt) pour la dérivation de clé

- Un champ `salt` unique et aléatoire est attribué à chaque utilisateur lors de l'inscription et stocké dans la base de données.
- Lors de la connexion, nous utilisons le mot de passe en clair fourni par l'utilisateur (avant qu'il ne soit vérifié contre le hash stocké) combiné avec le sel pour dériver la clé d'encryption personnelle.

```php
public static function deriveEncryptionKey(string $password, string $salt, int $length = 64, int $iteration = 80000): string {
    return hash_pbkdf2('sha256', $password, $salt, $iteration, $length);
}
```

#### Avantages de cette approche

- Même si la base de données est compromise (incluant les hashs de mots de passe et les sels), un attaquant ne peut pas générer les clés d'encryption sans les mots de passe en clair.
- Lors de la connexion, nous avons temporairement accès au mot de passe en clair, ce qui nous permet de générer la clé d'encryption sur demande.
- La clé d'encryption générée est ensuite chiffrée avec la clé de projet (définie dans `.env`) et stockée dans la session de l'utilisateur.
- Ce système de double chiffrement assure que même si la base de données est compromise, les données restent protégées.

Cette clé est chiffrée à l'aide d'une **clé de projet** définie dans le fichier `.env`, puis stockée temporairement dans la **session active** de l'utilisateur. Cela assure que même en cas de compromission de la base de données, les données restent illisibles sans la clé projet.

Aucune clé d'encryption n'est jamais stockée en clair dans la base. Le chiffrement est centralisé, découplé et basé sur la session Zephyrus, assurant un haut niveau de sécurité.

## Gestion des Authentifications MFA

L'application prend en charge plusieurs méthodes d'authentification multi-facteurs configurables par l'utilisateur :

- Courriel (Email)
- SMS
- Application authenticator (OTP, comme Google Authenticator)

Les clés OTP (TOTP secrets) utilisées pour les applications d'authentification sont également chiffrées en base avec la même logique de sécurité que les autres données sensibles.