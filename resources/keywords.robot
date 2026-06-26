*** Settings ***
Documentation    Keywords personnalisés réutilisés dans tous les tests
Library          SeleniumLibrary
Library          RequestsLibrary
Library          Collections
Resource         variables.robot


*** Keywords ***
# ------------------------------------------------------------------
# KEYWORDS UI (Selenium) - Authentification
# ------------------------------------------------------------------
Ouvrir Le Navigateur Sur La Page De Login
    Open Browser    ${LOGIN_URL}    ${BROWSER}
    Set Selenium Timeout    ${TIMEOUT}

Se Connecter Avec
    [Arguments]    ${username}    ${password}
    Input Text       ${USERNAME_FIELD}    ${username}
    Input Password   ${PASSWORD_FIELD}    ${password}
    Click Button     ${LOGIN_BUTTON}

Se Deconnecter
    [Documentation]    Sur Juice Shop, la déconnexion nécessite d'ouvrir le menu compte avant de cliquer sur logout
    Click Element    ${ACCOUNT_MENU}
    Click Element    ${LOGOUT_BUTTON}

Verifier Connexion Reussie
    Wait Until Element Is Visible    ${WELCOME_MESSAGE}    timeout=${TIMEOUT}

Verifier Connexion Refusee
    Wait Until Element Is Visible    ${ERROR_MESSAGE}    timeout=${TIMEOUT}

Fermer Le Navigateur Proprement
    Close Browser


# ------------------------------------------------------------------
# KEYWORDS API (RequestsLibrary)
# ------------------------------------------------------------------
Creer Session API
    Create Session    api    ${BASE_URL}

Envoyer Requete Login
    [Documentation]    Juice Shop attend {"email": ..., "password": ...} en JSON sur /rest/user/login
    [Arguments]    ${username}    ${password}
    ${body}=    Create Dictionary    email=${username}    password=${password}
    ${response}=    POST On Session    api    ${API_LOGIN_ENDPOINT}    json=${body}    expected_status=any
    RETURN    ${response}

Verifier Code Statut
    [Arguments]    ${response}    ${expected_code}
    Should Be Equal As Strings    ${response.status_code}    ${expected_code}


# ------------------------------------------------------------------
# KEYWORDS - Contrôle d'accès (IAM)
# ------------------------------------------------------------------
Acceder A Une Page Protegee
    [Arguments]    ${url}
    Go To    ${url}
    # Juice Shop étant une SPA Angular, laisser le temps au routeur de réagir
    Sleep    1s

Verifier Acces Refuse
    [Documentation]    Sur Juice Shop : redirection vers /login OU message d'erreur dans un toast.
    ...    À confirmer/ajuster en inspectant le comportement réel une fois l'app lancée.
    ${current_url}=    Get Location
    Should Not Contain    ${current_url}    administration

Verifier Acces Autorise
    [Documentation]    L'URL doit rester sur /#/administration et la page de données doit se charger
    ${current_url}=    Get Location
    Should Contain    ${current_url}    administration


# ------------------------------------------------------------------
# KEYWORDS - OWASP Top 10 (Injection / XSS)
# ------------------------------------------------------------------
Tester Injection SQL Sur Champ Login
    Se Connecter Avec    ${SQLI_PAYLOAD}    ${SQLI_PAYLOAD}
    Verifier Connexion Refusee

Tester Payload XSS Sur Champ
    [Arguments]    ${field_locator}
    Input Text    ${field_locator}    ${XSS_PAYLOAD}
    Page Should Not Contain    alert('x')


# ------------------------------------------------------------------
# KEYWORDS - Politique de mot de passe (logique pure, sans UI)
# ------------------------------------------------------------------
Le Mot De Passe Respecte La Politique
    [Arguments]    ${password}
    ${length_ok}=      Evaluate    len("""${password}""") >= 8
    ${has_upper}=      Evaluate    any(c.isupper() for c in """${password}""")
    ${has_lower}=      Evaluate    any(c.islower() for c in """${password}""")
    ${has_digit}=      Evaluate    any(c.isdigit() for c in """${password}""")
    ${has_special}=    Evaluate    any(not c.isalnum() for c in """${password}""")
    ${result}=         Evaluate    ${length_ok} and ${has_upper} and ${has_lower} and ${has_digit} and ${has_special}
    RETURN    ${result}

Le Mot De Passe Depasse La Longueur Maximale
    [Documentation]    Vérifie qu'un mot de passe anormalement long est rejeté (protection anti-DoS)
    [Arguments]    ${password}
    ${too_long}=    Evaluate    len("""${password}""") > ${MAX_PASSWORD_LENGTH}
    RETURN    ${too_long}

Le Mot De Passe Est Identique Au Nom Utilisateur
    [Documentation]    Vérifie qu'un utilisateur ne réutilise pas son propre identifiant comme mot de passe
    [Arguments]    ${username}    ${password}
    ${same}=    Evaluate    """${username}""".lower() == """${password}""".lower()
    RETURN    ${same}

Le Mot De Passe Est Dans La Liste Noire
    [Documentation]    Vérifie qu'un mot de passe ne fait pas partie des mots de passe les plus courants/faibles
    [Arguments]    ${password}
    ${normalized}=    Evaluate    """${password}""".lower()
    ${is_blacklisted}=    Evaluate    """${normalized}""" in ${PASSWORD_BLACKLIST}
    RETURN    ${is_blacklisted}

Le Mot De Passe Contient Uniquement Des Espaces
    [Documentation]    Vérifie qu'un mot de passe composé uniquement d'espaces est rejeté
    [Arguments]    ${password}
    ${blank}=    Evaluate    """${password}""".strip() == ""
    RETURN    ${blank}
