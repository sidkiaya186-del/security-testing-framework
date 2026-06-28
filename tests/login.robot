*** Settings ***
Documentation       Tests de connexion / déconnexion
Resource             ../resources/variables.robot
Resource             ../resources/keywords.robot
Suite Setup          Ouvrir Le Navigateur Sur La Page De Login
Suite Teardown       Fermer Le Navigateur Proprement
Test Teardown        Reinitialiser Etat Pour Test Suivant
Test Tags            authentification

*** Test Cases ***
Connexion Avec Identifiants Valides
    [Documentation]    Vérifie que l'utilisateur peut se connecter avec des identifiants corrects
    Se Connecter Avec    ${VALID_USER}    ${VALID_PASSWORD}
    Verifier Connexion Reussie

Connexion Avec Identifiants Invalides
    [Documentation]    Vérifie que la connexion est refusée avec des identifiants incorrects
    Se Connecter Avec    ${INVALID_USER}    ${INVALID_PASSWORD}
    Verifier Connexion Refusee

Deconnexion Reussie
    [Documentation]    Vérifie que la déconnexion supprime bien le token d'authentification
    Se Connecter Avec    ${VALID_USER}    ${VALID_PASSWORD}
    Verifier Connexion Reussie
    Se Deconnecter
    Verifier Deconnexion Reussie