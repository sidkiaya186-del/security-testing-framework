*** Settings ***
Documentation       Vérifie le contrôle d'accès (IAM) entre utilisateur normal et administrateur
Resource             ../resources/variables.robot
Resource             ../resources/keywords.robot
Suite Setup          Ouvrir Le Navigateur Sur La Page De Login
Suite Teardown       Fermer Le Navigateur Proprement
Test Tags            iam    access-control


*** Test Cases ***
Utilisateur Normal Ne Peut Pas Acceder A L Admin
    [Documentation]    Un utilisateur sans privilèges doit recevoir un accès refusé sur /admin
    Se Connecter Avec    ${NORMAL_USER}    ${NORMAL_PASSWORD}
    Verifier Connexion Reussie
    Acceder A Une Page Protegee    ${ADMIN_URL}
    Verifier Acces Refuse

Administrateur Peut Acceder A L Admin
    [Documentation]    Un utilisateur avec privilèges admin doit accéder à /admin
    Se Connecter Avec    ${VALID_USER}    ${VALID_PASSWORD}
    Verifier Connexion Reussie
    Acceder A Une Page Protegee    ${ADMIN_URL}
    Verifier Acces Autorise

Acces Direct Sans Authentification Est Refuse
    [Documentation]    Vérifie qu'on ne peut pas atteindre /admin sans être connecté (pas de session)
    Acceder A Une Page Protegee    ${ADMIN_URL}
    Verifier Acces Refuse
