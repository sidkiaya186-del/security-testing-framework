*** Settings ***
Documentation    Vérifie que la politique de mot de passe est correctement appliquée
Resource         ../resources/variables.robot
Resource         ../resources/keywords.robot
Test Tags        password-policy


*** Test Cases ***
# ------------------------------------------------------------------
# Règles de base (longueur, majuscule, chiffre, caractère spécial)
# ------------------------------------------------------------------
Mot De Passe Valide Est Accepte
    [Documentation]    Password123! respecte toutes les règles
    ${result}=    Le Mot De Passe Respecte La Politique    Password123!
    Should Be True    ${result}

Mot De Passe Trop Court Est Refuse
    ${result}=    Le Mot De Passe Respecte La Politique    Pa1!
    Should Not Be True    ${result}

Mot De Passe Sans Majuscule Est Refuse
    ${result}=    Le Mot De Passe Respecte La Politique    password123!
    Should Not Be True    ${result}

Mot De Passe Sans Chiffre Est Refuse
    ${result}=    Le Mot De Passe Respecte La Politique    Password!
    Should Not Be True    ${result}

Mot De Passe Sans Caractere Special Est Refuse
    ${result}=    Le Mot De Passe Respecte La Politique    Password123
    Should Not Be True    ${result}

Mot De Passe Numerique Seul Est Refuse
    ${result}=    Le Mot De Passe Respecte La Politique    123
    Should Not Be True    ${result}


# ------------------------------------------------------------------
# Cas avancés
# ------------------------------------------------------------------
Mot De Passe Identique Au Nom Utilisateur Est Refuse
    [Documentation]    Empêche l'utilisateur de prendre son propre login comme mot de passe
    ${result}=    Le Mot De Passe Est Identique Au Nom Utilisateur    aya.sidki    aya.sidki
    Should Be True    ${result}

Mot De Passe Identique Au Nom Utilisateur Insensible A La Casse
    [Documentation]    AYA.SIDKI vs aya.sidki doit être détecté comme identique
    ${result}=    Le Mot De Passe Est Identique Au Nom Utilisateur    aya.sidki    AYA.SIDKI
    Should Be True    ${result}

Mot De Passe Different Du Nom Utilisateur Est Accepte
    ${result}=    Le Mot De Passe Est Identique Au Nom Utilisateur    aya.sidki    Password123!
    Should Not Be True    ${result}

Mot De Passe Compose Uniquement Despaces Est Refuse
    [Documentation]    Un mot de passe "   " ne doit pas être accepté comme valide
    ${result}=    Le Mot De Passe Contient Uniquement Des Espaces    ${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}${SPACE}
    Should Be True    ${result}

Mot De Passe Normal Nest Pas Considere Comme Vide
    ${result}=    Le Mot De Passe Contient Uniquement Des Espaces    Password123!
    Should Not Be True    ${result}

Mot De Passe Trop Long Est Refuse
    [Documentation]    Protection anti-DoS : un mot de passe de 500 caractères doit être rejeté
    ${long_password}=    Evaluate    "A1!" * 200
    ${result}=    Le Mot De Passe Depasse La Longueur Maximale    ${long_password}
    Should Be True    ${result}

Mot De Passe De Longueur Normale Nest Pas Rejete Pour Sa Taille
    ${result}=    Le Mot De Passe Depasse La Longueur Maximale    Password123!
    Should Not Be True    ${result}

Mot De Passe Courant Dans La Liste Noire Est Refuse
    [Documentation]    "password123" est un des mots de passe les plus utilisés au monde
    ${result}=    Le Mot De Passe Est Dans La Liste Noire    password123
    Should Be True    ${result}

Mot De Passe Courant Liste Noire Insensible A La Casse
    ${result}=    Le Mot De Passe Est Dans La Liste Noire    PASSWORD123
    Should Be True    ${result}

Mot De Passe Original Nest Pas Dans La Liste Noire
    ${result}=    Le Mot De Passe Est Dans La Liste Noire    Xk9$mPlq2024!
    Should Not Be True    ${result}


# ------------------------------------------------------------------
# Test paramétré (Template) - même vérification, plusieurs jeux de données
# Avantage : un seul keyword, lisibilité en tableau, facile à étendre
# ------------------------------------------------------------------
Validation Groupee De La Politique De Mot De Passe
    [Template]    Verifier Conformite Mot De Passe
    Password123!         ${TRUE}     # valide : toutes les règles respectées
    password123!         ${FALSE}    # invalide : pas de majuscule
    PASSWORD123!         ${FALSE}    # invalide : pas de minuscule
    Password!             ${FALSE}    # invalide : pas de chiffre
    Password123           ${FALSE}    # invalide : pas de caractère spécial
    Pa1!                  ${FALSE}    # invalide : trop court
    Tr3s$ecur3P@ssw0rd     ${TRUE}     # valide : mot de passe fort réaliste


*** Keywords ***
Verifier Conformite Mot De Passe
    [Arguments]    ${password}    ${expected}
    ${result}=    Le Mot De Passe Respecte La Politique    ${password}
    Should Be Equal As Strings    ${result}    ${expected}
