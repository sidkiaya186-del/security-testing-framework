# Security Testing Automation Framework

Framework d'automatisation de tests de sécurité basé sur **Robot Framework**, conçu pour auditer automatiquement les fonctionnalités de sécurité critiques d'une application web : authentification, politique de mot de passe, gestion des comptes, contrôle d'accès (IAM), API, et vulnérabilités OWASP Top 10 de base (Injection SQL, XSS).

## Objectif

Démontrer une approche **DevSecOps** : intégrer des tests de sécurité directement dans un pipeline CI/CD, déclenchés à chaque push, avec génération automatique d'un rapport HTML.

## Architecture

```
security-testing-framework/
│
├── tests/
│   ├── login.robot           # Authentification (connexion / déconnexion)
│   ├── password.robot        # Politique de mot de passe
│   ├── authorization.robot   # Contrôle d'accès IAM (user vs admin)
│   └── api.robot              # Tests API + OWASP Top 10 (SQLi, XSS, headers)
│
├── resources/
│   ├── keywords.robot         # Keywords réutilisables (UI + API)
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

## Prérequis

- Python 3.9+
- Google Chrome + ChromeDriver (pour les tests Selenium)
- Une application cible vulnérable pour les tests (recommandé : [DVWA](https://github.com/digininja/DVWA) ou [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), à lancer via Docker en local)

## Installation

```bash
git clone <ton-repo>
cd security-testing-framework
pip install -r requirements.txt
```

Lancer l'application cible (exemple avec DVWA) :

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

## Configuration

Avant de lancer les tests, adapter dans `resources/variables.robot` :
- `${BASE_URL}` : l'URL de ton application cible
- Les sélecteurs Selenium (`${USERNAME_FIELD}`, `${LOGIN_BUTTON}`, etc.) selon le DOM réel de l'application

## Exécution des tests

Tous les tests :
```bash
robot --outputdir reports tests/
```

Une suite spécifique :
```bash
robot --outputdir reports tests/login.robot
```

Par tag (ex : uniquement les tests IAM) :
```bash
robot --outputdir reports --include iam tests/
```

## Rapport

Après exécution, ouvrir `reports/report.html` dans un navigateur pour consulter :
- Le résumé pass/fail par suite
- Les logs détaillés étape par étape (`reports/log.html`)

## Pipeline CI/CD

Le fichier `.github/workflows/robot-tests.yml` exécute automatiquement les tests à chaque `push` ou `pull_request` sur `main`/`develop` :

```
Push GitHub → Installation deps → Lancement app cible (Docker)
            → Exécution Robot Framework → Rapport HTML → Artifact téléchargeable
```

Le rapport est disponible en tant qu'**artifact GitHub Actions** après chaque exécution (onglet "Actions" → run → "Artifacts").

## Tests couverts

| Module | Cas de test |
|---|---|
| Authentification | Login valide, login invalide, déconnexion |
| Mot de passe | Longueur, majuscule, chiffre, caractère spécial |
| IAM | Accès user normal vs admin sur `/admin` |
| API | Codes HTTP 200/401/403, headers de sécurité (HSTS, CSP) |
| OWASP Top 10 | Injection SQL (`' OR 1=1 --`), XSS (`<script>alert('x')</script>`) |

## Avertissement

Ce framework est destiné à être utilisé **uniquement sur des applications de test volontairement vulnérables (DVWA, Juice Shop, bWAPP)** ou sur des applications pour lesquelles tu as une autorisation explicite. Ne jamais l'exécuter contre une application en production sans accord écrit.

## Pistes d'amélioration

- Ajout de tests CRUD complets sur la gestion des comptes (création/suppression/modification)
- Intégration d'un scan OWASP ZAP en parallèle (ZAP API + parsing des résultats dans le rapport)
- Audit TLS/SSL (versions de protocole, cipher suites) via un script Python complémentaire
