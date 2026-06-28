*** Settings ***
Documentation    Variables globales partagées par tous les tests
...              Configurées pour OWASP Juice Shop (https://github.com/juice-shop/juice-shop)

*** Variables ***
# --- URL de l'application cible (OWASP Juice Shop) ---
${BASE_URL}             http://localhost:3000
${LOGIN_URL}            ${BASE_URL}/#/login
${ADMIN_URL}            ${BASE_URL}/#/administration
${API_LOGIN_ENDPOINT}   /rest/user/login

# --- Identifiants de test ---
# IMPORTANT : Juice Shop ne fournit pas de comptes par défaut (sauf admin@juice-sh.op
# dont le mot de passe doit être retrouvé via un challenge, ou un compte que tu crées toi-même
# via /#/register). Crée un compte de test "normal" et, si possible, élève un compte en admin
# via le challenge "Database schema" / JWT du projet une fois familiarisé avec l'app.
${VALID_USER}           testuser@example.com
${VALID_PASSWORD}       Test1234!
${INVALID_USER}         hacker@evil.com
${INVALID_PASSWORD}     wrongpass

${NORMAL_USER}          testuser@example.com
${NORMAL_PASSWORD}      Test1234!

# Compte admin obtenu via une faille de mass assignment sur POST /api/Users
# (le champ "role":"admin" n'est pas filtré côté serveur - vulnérabilité réelle
# et volontaire de Juice Shop, catégorie OWASP API3:2023 Broken Object Property
# Level Authorization). Voir README.md, section "Vulnérabilités découvertes".
${ADMIN_USER}           admin-test@example.com
${ADMIN_PASSWORD}       AdminTest123!

# --- Sélecteurs Selenium (DOM réel de Juice Shop, Angular Material) ---
${USERNAME_FIELD}       id=email
${PASSWORD_FIELD}       id=password
${LOGIN_BUTTON}         id=loginButton
${ACCOUNT_MENU}         id=navbarAccount
${LOGOUT_BUTTON}        id=navbarLogoutButton
# Le message d'erreur apparaît dans un toast Angular Material (texte exact à reconfirmer
# en inspectant le DOM réel, car il peut varier selon la version de Juice Shop)
${ERROR_MESSAGE}        xpath=//*[contains(text(),'Invalid email or password')]
# Présence de l'icône de compte = connexion réussie (pas de "message de bienvenue" dédié)
${WELCOME_MESSAGE}      id=navbarAccount

# --- Navigateur ---
${BROWSER}              headlesschrome
${TIMEOUT}              10s

# --- Payloads OWASP ---
${SQLI_PAYLOAD}         ' OR 1=1 --
${XSS_PAYLOAD}          <script>alert('x')</script>

# --- Politique de mot de passe avancée ---
${MAX_PASSWORD_LENGTH}    128

@{PASSWORD_BLACKLIST}
...    password
...    password123
...    azerty123
...    123456789
...    motdepasse
...    admin123
...    qwerty123
