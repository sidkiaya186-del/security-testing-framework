*** Settings ***
Documentation     Sécurité : Vérification des cookies de session et des en-têtes HTTP
...               Cible : OWASP Juice Shop (localhost:3000)
Library           RequestsLibrary
Library           Collections

*** Variables ***
${BASE_URL}       http://localhost:3000
${LOGIN_ENDPOINT}    /rest/user/login
${VALID_EMAIL}    admin@juice-sh.op
${VALID_PASSWORD}    admin123

*** Test Cases ***
Headers De Securite Presents Sur La Page Principale
    [Documentation]    Vérifie la présence des headers de sécurité recommandés (OWASP A05)
    ${response}=    GET    ${BASE_URL}/    expected_status=200
    ${headers}=    Set Variable    ${response.headers}

    Log    Headers reçus: ${headers}

    Run Keyword And Continue On Failure
    ...    Dictionary Should Contain Key    ${headers}    x-content-type-options
    ...    msg=FAILLE: header X-Content-Type-Options absent (risque MIME sniffing)

    Run Keyword And Continue On Failure
    ...    Dictionary Should Contain Key    ${headers}    x-frame-options
    ...    msg=FAILLE: header X-Frame-Options absent (risque clickjacking)

    Run Keyword And Continue On Failure
    ...    Dictionary Should Contain Key    ${headers}    content-security-policy
    ...    msg=FAILLE: header Content-Security-Policy absent (risque XSS/injection)

    Run Keyword And Continue On Failure
    ...    Dictionary Should Contain Key    ${headers}    strict-transport-security
    ...    msg=FAILLE: header Strict-Transport-Security absent (risque downgrade HTTPS)

Header X-Powered-By Ne Doit Pas Exposer La Techno
    [Documentation]    Vérifie que le serveur ne fuit pas d'infos techniques (OWASP A05 - fingerprinting)
    ${response}=    GET    ${BASE_URL}/    expected_status=200
    ${headers}=    Set Variable    ${response.headers}

    ${exposed}=    Run Keyword And Return Status
    ...    Dictionary Should Contain Key    ${headers}    x-powered-by

    Run Keyword If    ${exposed}
    ...    Log    FAILLE: header X-Powered-By expose la stack technique    level=WARN

Cookie De Session Doit Avoir Le Flag HttpOnly
    [Documentation]    Vérifie que le cookie de session n'est pas accessible en JS (protection XSS)
    Create Session    juiceshop    ${BASE_URL}
    ${body}=    Create Dictionary    email=${VALID_EMAIL}    password=${VALID_PASSWORD}
    ${response}=    POST On Session    juiceshop    ${LOGIN_ENDPOINT}    json=${body}

    ${set_cookie}=    Run Keyword And Return Status
    ...    Dictionary Should Contain Key    ${response.headers}    set-cookie

    IF    ${set_cookie}
        ${cookie_value}=    Get From Dictionary    ${response.headers}    set-cookie
        ${has_httponly}=    Run Keyword And Return Status
        ...    Should Contain    ${cookie_value}    HttpOnly
        Run Keyword If    not ${has_httponly}
        ...    Log    FAILLE: cookie de session sans flag HttpOnly (vulnérable au vol via XSS)    level=WARN
    END

Mot De Passe Ne Doit Jamais Apparaitre En Clair Dans La Reponse API
    [Documentation]    Vérifie qu'aucune réponse API ne renvoie le mot de passe en clair (OWASP A02)
    Create Session    juiceshop2    ${BASE_URL}
    ${body}=    Create Dictionary    email=${VALID_EMAIL}    password=${VALID_PASSWORD}
    ${response}=    POST On Session    juiceshop2    ${LOGIN_ENDPOINT}    json=${body}

    Should Not Contain    ${response.text}    ${VALID_PASSWORD}
    ...    msg=FAILLE CRITIQUE: le mot de passe est renvoyé en clair dans la réponse API
