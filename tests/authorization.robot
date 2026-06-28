*** Settings ***
Documentation       Vérifie le contrôle d'accès (IAM) entre utilisateur normal et administrateur
Resource             ../resources/variables.robot
Resource             ../resources/keywords.robot
Suite Setup          Ouvrir Le Navigateur Sur La Page De Login
Suite Teardown       Fermer Le Navigateur Proprement
Test Teardown        Reinitialiser Etat Pour Test Suivant
Test Tags            iam    access-control


*** Test Cases ***
Utilisateur Normal Ne Peut Pas Acceder A L Admin
    [Documentation]    Un utilisateur connecté sans privilèges admin doit être redirigé
    ...    silencieusement hors de /administration (pas de message d'erreur, comportement
    ...    différent du cas anonyme).
    Se Connecter Avec    ${NORMAL_USER}    ${NORMAL_PASSWORD}
    Verifier Connexion Reussie
    Acceder A Une Page Protegee    ${ADMIN_URL}
    Verifier Acces Refuse Utilisateur Normal

Acces Direct Sans Authentification Est Refuse
    [Documentation]    Sans être connecté du tout, Juice Shop affiche un message 403 explicite
    Acceder A Une Page Protegee    ${ADMIN_URL}
    Verifier Acces Refuse Anonyme

Administrateur Peut Acceder A L Admin
    [Documentation]    Un utilisateur avec privilèges admin doit accéder à /administration
    ...    et voir les données réelles (pas le message 403).
    ...    Compte admin obtenu via une faille de mass assignment sur POST /api/Users
    ...    (voir README.md, section "Vulnérabilités découvertes").
    Se Connecter Avec    ${ADMIN_USER}    ${ADMIN_PASSWORD}
    Verifier Connexion Reussie
    Acceder A Une Page Protegee    ${ADMIN_URL}
    Verifier Acces Autorise