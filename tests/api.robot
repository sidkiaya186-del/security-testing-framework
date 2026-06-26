*** Settings ***
Documentation       Tests de sécurité via l'API REST + vérifications OWASP Top 10 (cible : OWASP Juice Shop)
Resource             ../resources/variables.robot
Resource             ../resources/keywords.robot
Suite Setup          Creer Session API
Test Tags            api    owasp


*** Test Cases ***
Login API Avec Identifiants Valides Retourne 200
    [Documentation]    Nécessite un compte créé au préalable via /#/register
    ${response}=    Envoyer Requete Login    ${VALID_USER}    ${VALID_PASSWORD}
    Verifier Code Statut    ${response}    200

Login API Avec Mot De Passe Incorrect Retourne 401
    ${response}=    Envoyer Requete Login    ${VALID_USER}    ${INVALID_PASSWORD}
    Verifier Code Statut    ${response}    401

Login API Sans Droits Suffisants Retourne 403 Sur Ressource Protegee
    [Documentation]    NOTE : l'endpoint exact dépend de la version de Juice Shop
    ...    (ex : /api/Users nécessite un token admin valide). À ajuster une fois l'app lancée,
    ...    en observant les appels réseau (onglet Network du navigateur) pendant la navigation
    ...    sur /#/administration en tant qu'utilisateur non-admin.
    ${session}=    Envoyer Requete Login    ${NORMAL_USER}    ${NORMAL_PASSWORD}
    Verifier Code Statut    ${session}    200
    ${response}=    GET On Session    api    /api/Users    expected_status=any
    Verifier Code Statut    ${response}    403

Injection SQL Sur Endpoint Login Est Bloquee
    [Documentation]    ATTENTION : Juice Shop contient volontairement un challenge historique de
    ...    bypass d'authentification via SQLi sur ce endpoint ('OR 1=1--). Si ce test ÉCHOUE,
    ...    ce n'est pas un bug de ton framework : c'est ton framework qui a détecté la vraie
    ...    vulnérabilité que l'app est censée contenir. C'est un excellent résultat à présenter :
    ...    "mon test a confirmé/découvert la faille SQLi attendue".
    ${response}=    Envoyer Requete Login    ${SQLI_PAYLOAD}    ${SQLI_PAYLOAD}
    Verifier Code Statut    ${response}    401

Payload XSS Sur Endpoint Login Nest Pas Reflete
    [Documentation]    Vérifie que le payload XSS n'est pas renvoyé tel quel dans la réponse
    ${response}=    Envoyer Requete Login    ${XSS_PAYLOAD}    test123
    Should Not Contain    ${response.text}    <script>alert('x')</script>

En Tete De Securite HSTS Present
    [Documentation]    NOTE : Juice Shop étant une app volontairement vulnérable, il est possible
    ...    que ce header soit ABSENT par défaut. Un échec ici documente une vraie faiblesse de
    ...    configuration (Security Misconfiguration, OWASP A05) — résultat pertinent à signaler.
    ${response}=    GET On Session    api    /    expected_status=any
    Dictionary Should Contain Key    ${response.headers}    Strict-Transport-Security

En Tete De Securite CSP Present
    [Documentation]    Même remarque que pour HSTS ci-dessus.
    ${response}=    GET On Session    api    /    expected_status=any
    Dictionary Should Contain Key    ${response.headers}    Content-Security-Policy
