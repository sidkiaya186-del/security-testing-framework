Voici le contenu complet à coller dans `README.md`, en remplaçant tout le fichier :

```markdown
# Security Testing Automation Framework

Framework d'automatisation de tests de sécurité basé sur **Robot Framework**, conçu pour auditer automatiquement les fonctionnalités de sécurité critiques d'une application web : authentification, politique de mot de passe, contrôle d'accès (IAM), API REST, et vulnérabilités OWASP Top 10.

Testé en conditions réelles contre **[OWASP Juice Shop](https://github.com/juice-shop/juice-shop)** — 31 tests automatisés, 4 vulnérabilités réelles découvertes et documentées (voir plus bas).

## Objectif

Démontrer une approche **DevSecOps** : intégrer des tests de sécurité directement dans un pipeline CI/CD, déclenchés à chaque push, avec génération automatique d'un rapport HTML.

## Architecture

```
security-testing-framework/
│
├── tests/
│   ├── login.robot           # Authentification (connexion / déconnexion)
│   ├── password.robot        # Politique de mot de passe (17 tests, logique pure)
│   ├── authorization.robot   # Contrôle d'accès IAM (user normal vs admin)
│   └── api.robot              # Tests API REST + confirmations de failles OWASP
│
├── resources/
│   ├── keywords.robot         # Keywords réutilisables (UI Selenium + API + logique)
│   └── variables.robot        # Variables globales (URLs, identifiants, payloads)
│
├── reports/                   # Rapports générés (log.html, report.html, output.xml)
│
├── .github/workflows/
│   └── robot-tests.yml        # Pipeline CI/CD GitHub Actions
│
├── requirements.txt
└── README.md
```

## Résultats actuels

| Suite | Résultat | Détail |
|---|---|---|
| `password.robot` | ✅ 17/17 PASS | Complexité, identité utilisateur, anti-DoS, liste noire, test paramétré |
| `login.robot` | ✅ 3/3 PASS | Connexion valide/invalide, déconnexion (vérification du token JWT) |
| `authorization.robot` | ✅ 3/3 PASS | Anonyme, utilisateur normal, admin (obtenu via faille mass assignment) |
| `api.robot` | ✅ 8/8 PASS | 3 comportements standards + 5 confirmations de failles réelles |
| **Total** | **✅ 31/31 PASS** | |

## Vulnérabilités découvertes

Le tag `vulnerabilite-confirmee` (dans `api.robot`) regroupe des tests conçus pour **confirmer la présence de failles réelles**, plutôt que d'espérer une sécurité absente. Ces tests sont **verts quand la faille est détectée** (documentation active) ; ils passeraient au rouge si l'application venait à être corrigée (tests de non-régression de vulnérabilité).

| # | Vulnérabilité | Catégorie OWASP | Endpoint | Preuve |
|---|---|---|---|---|
| 1 | **Bypass d'authentification par injection SQL** | API2:2023 Broken Authentication | `POST /rest/user/login` | Le payload `' OR 1=1 --` dans email/password renvoie `200 OK` avec un token valide, sans connaître de vrai mot de passe |
| 2 | **Broken Function Level Authorization** | API5:2023 | `GET /api/Users` | Un token d'utilisateur **non-admin** suffit pour lister tous les comptes (`200 OK`) ; le contrôle de rôle n'existe que côté frontend (`/#/administration`), pas côté backend |
| 3 | **Mass Assignment** | API3:2023 | `POST /api/Users` | Le champ `"role":"admin"` envoyé librement dans le corps de la requête d'inscription est accepté sans filtrage serveur — élévation de privilèges immédiate |
| 4 | **Security Misconfiguration (headers manquants)** | A05:2021 | `GET /` | Absence des headers `Strict-Transport-Security` et `Content-Security-Policy` |

**Méthodologie** : chaque faille a été découverte via les tests automatisés du framework lui-même, puis confirmée manuellement (requête `Invoke-RestMethod` / inspection navigateur) avant d'être formalisée en test reproductible.

## Prérequis

- Python 3.9+
- Google Chrome (le ChromeDriver est géré automatiquement par Selenium 4.25+)
- Docker (pour lancer OWASP Juice Shop en local)

## Installation

```bash
git clone <ton-repo>
cd security-testing-framework
pip install -r requirements.txt
```

Lancer l'application cible :

```bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

Puis créer un compte de test via `http://localhost:3000/#/register`.

## Configuration

Dans `resources/variables.robot` :
- `${BASE_URL}` : URL de l'application cible (par défaut `http://localhost:3000`)
- `${VALID_USER}` / `${NORMAL_USER}` : doivent correspondre à un compte réellement créé
- `${ADMIN_USER}` : compte admin — peut être obtenu via la faille de mass assignment documentée ci-dessus :
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:3000/api/Users" -Method Post -ContentType "application/json" -Body '{"email":"TON_EMAIL","password":"TON_MDP","role":"admin"}'
  ```

## Exécution des tests

Tous les tests :
```bash
robot --outputdir reports tests/
```

Une suite spécifique :
```bash
robot --outputdir reports tests/password.robot
```

Avec navigateur visible (debug) au lieu du mode headless :
```bash
robot --outputdir reports --variable BROWSER:chrome tests/login.robot
```

Uniquement les vulnérabilités confirmées :
```bash
robot --outputdir reports --include vulnerabilite-confirmee tests/api.robot
```

## Rapport

Après exécution, ouvrir `reports/report.html` dans un navigateur pour consulter le résumé pass/fail, et `reports/log.html` pour le détail étape par étape (utile notamment pour voir les messages `FAILLE CONFIRMÉE : ...` loggés dans la console).

## Pipeline CI/CD

Le fichier `.github/workflows/robot-tests.yml` exécute automatiquement les tests à chaque `push` ou `pull_request` sur `main`/`develop`, et publie le rapport HTML en artifact téléchargeable (onglet "Actions" du repo GitHub).

## Difficultés rencontrées et résolues

Quelques problèmes réels rencontrés pendant le développement, pour donner une idée du travail de debug effectué :

- **`ElementClickInterceptedException`** : un bandeau "Welcome" (mat-dialog Angular Material) bloquait les clics sur le bouton de login au premier chargement → keyword dédié pour le fermer avec plusieurs sélecteurs de repli
- **`StaleElementReferenceException`** : les tests partageaient une session de navigateur sans réinitialisation → ajout d'un `Test Teardown` qui efface cookies/localStorage entre chaque test
- **Déconnexion non détectable par redirection** : Juice Shop ne redirige pas systématiquement vers `/login` après logout → vérification basée sur la suppression du token JWT plutôt que sur l'UI
- **Comportement IAM différent selon le contexte** : un utilisateur anonyme reçoit un message "403" explicite, alors qu'un utilisateur connecté sans droits est redirigé silencieusement — deux keywords de vérification distincts ont été nécessaires

## Avertissement

Ce framework est destiné à être utilisé **uniquement sur des applications de test volontairement vulnérables** (OWASP Juice Shop, DVWA, bWAPP) ou sur des applications pour lesquelles une autorisation explicite a été obtenue. Ne jamais l'exécuter contre une application en production sans accord écrit.

## Pistes d'amélioration

- Ajout de tests CRUD complets sur la gestion des comptes (création/suppression/modification)
- Intégration d'un scan OWASP ZAP en parallèle (ZAP API + parsing des résultats dans le rapport)
- Audit TLS/SSL (versions de protocole, cipher suites) via un script Python complémentaire
- Étendre la détection de Broken Function Level Authorization à d'autres endpoints `/api/`
```