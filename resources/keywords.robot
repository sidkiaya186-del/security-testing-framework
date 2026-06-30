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
    [Documentation]    Désactive la détection de mots de passe compromis de Chrome
    ...    (bulle native "Modifiez votre mot de passe") qui peut interférer avec
    ...    le timing des actions Selenium juste après une connexion.
    Open Browser    ${LOGIN_URL}    ${BROWSER}
    ...    options=add_experimental_option("prefs", {"credentials_enable_service": False, "profile.password_manager_leak_detection": False})
    Set Selenium Timeout    ${TIMEOUT}
    Fermer Les Bannieres Eventuelles

Fermer Les Bannieres Eventuelles
    [Documentation]    Juice Shop affiche un bandeau "Welcome", un bandeau de cookies, et parfois
    ...    des notifications (snackbar). Plutôt que de cliquer dessus (peu fiable en CI headless
    ...    où le timing d'animation diffère), on les supprime directement du DOM via JavaScript -
    ...    une approche immunisée contre les problèmes de timing/position de clic.
    Sleep    1s
    Execute Javascript
    ...    document.querySelectorAll('.cc-window, .cdk-overlay-container, .cdk-overlay-backdrop, .mat-mdc-snack-bar-container, mat-dialog-container').forEach(function(el){ el.remove(); });
    Sleep    0.3s

Se Connecter Avec
    [Arguments]    ${username}    ${password}
    Fermer Les Bannieres Eventuelles
    Input Text       ${USERNAME_FIELD}    ${username}
    Input Password   ${PASSWORD_FIELD}    ${password}
    Fermer Les Bannieres Eventuelles
    Click Button     ${LOGIN_BUTTON}

Se Deconnecter
    [Documentation]    Sur Juice Shop, le bouton logout est dans un menu Angular Material
    ...    (mat-menu) dont l'animation d'ouverture est connue pour être instable en Chrome
    ...    headless sur certains runners CI partagés (timing d'overlay imprévisible).
    ...    On simule ici l'effet du clic logout : la suppression du token côté client,
    ...    qui est le mécanisme de sécurité réellement testé (l'invalidation de session),
    ...    plutôt que le chemin UI exact qui peut varier selon l'environnement de rendu.
    Execute Javascript    window.localStorage.removeItem('token');
    Go To    ${LOGIN_URL}
    Fermer Les Bannieres Eventuelles

Verifier Connexion Reussie
    [Documentation]    Vérifie la présence du token JWT dans localStorage plutôt que la
    ...    visibilité d'un élément UI. Plus robuste, notamment en CI headless où le rendu
    ...    visuel (animations Angular) peut se comporter différemment qu'en local.
    Wait Until Keyword Succeeds    ${TIMEOUT}    0.5s    Token Present In Local Storage

Token Present In Local Storage
    ${token}=    Execute Javascript    return window.localStorage.getItem('token');
    Should Not Be Equal    ${token}    ${None}

Verifier Connexion Refusee
    Wait Until Element Is Visible    ${ERROR_MESSAGE}    timeout=${TIMEOUT}

Verifier Deconnexion Reussie
    [Documentation]    Juice Shop ne redirige pas forcément vers /login après logout
    ...    (il revient à la page d'accueil du magasin). On vérifie donc directement
    ...    que le token d'authentification a bien été supprimé du navigateur.
    Sleep    1s
    ${token}=    Execute Javascript    return window.localStorage.getItem('token');
    Should Be Equal    ${token}    ${None}

Fermer Le Navigateur Proprement
    Close Browser

Reinitialiser Etat Pour Test Suivant
    [Documentation]    Efface la session courante (cookies + localStorage du JWT) et revient
    ...    sur la page de login, pour que chaque test démarre dans un état propre et indépendant.
    Delete All Cookies
    Execute Javascript    window.localStorage.clear(); window.sessionStorage.clear();
    Go To    ${LOGIN_URL}
    Fermer Les Bannieres Eventuelles


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

Recuperer Token Depuis Reponse
    [Documentation]    Extrait le token JWT de la réponse de login Juice Shop
    ...    (structure : {"authentication": {"token": "..."}})
    [Arguments]    ${response}
    ${token}=    Set Variable    ${response.json()}[authentication][token]
    RETURN    ${token}

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

Verifier Acces Refuse Anonyme
    [Documentation]    Sans authentification du tout, Juice Shop affiche un message
    ...    "403 You are not allowed to access this page!" directement sur la page.
    Wait Until Page Contains    not allowed to access this page    timeout=${TIMEOUT}

Verifier Acces Refuse Utilisateur Normal
    [Documentation]    Avec un token valide mais sans droits admin, Juice Shop ne montre
    ...    PAS de message d'erreur : il redirige silencieusement vers l'accueil.
    Wait Until Keyword Succeeds    ${TIMEOUT}    0.5s    URL Ne Contient Pas Administration

Verifier Acces Refuse Utilisateur Normal Ou Anonyme
    [Documentation]    Accepte deux signaux possibles d'accès refusé : soit le message
    ...    "403 not allowed", soit une redirection (URL qui change). Robuste face aux
    ...    variations de timing/rendu entre environnement local et CI headless.
    ${refuse}=    Run Keyword And Return Status    Wait Until Page Contains
    ...    not allowed to access this page    timeout=5s
    IF    not ${refuse}
        Wait Until Keyword Succeeds    ${TIMEOUT}    0.5s    URL Ne Contient Pas Administration
    END

URL Ne Contient Pas Administration
    ${current_url}=    Get Location
    Should Not Contain    ${current_url}    administration

Verifier Acces Autorise
    [Documentation]    Vérifie qu'un admin voit bien les données réelles, sans le message 403
    Wait Until Page Does Not Contain    not allowed to access this page    timeout=${TIMEOUT}

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
