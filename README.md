> ⚠️ **Statut :** phases 0 à 4 terminées · threat hunting et gestion des vulnérabilités en cours + captures d'écrans à prendre.
# 🛡️ SOC Lab · Microsoft Defender XDR et Sentinel



Laboratoire SecOps Microsoft monté de zéro dans un seul tenant ; expérience pratique pour la certification **SC-200 (Microsoft Security Operations Analyst)**.

> Chaque phase est documentée de bout en bout, y compris ce qui a échoué et comment je l'ai corrigé :
```
ingestion → détection → automatisation → investigation → hunting → gestion des vulnérabilités
```
---

## 🎯 Objectif

Pratiquer chaque compétence mesurée par la SC-200 dans un vrai tenant, plutôt que de l'étudier seulement en théorie :

- **Microsoft Sentinel** comme SIEM, sur un workspace Log Analytics
- **Defender XDR** et **Defender for Endpoint** dans le portail Defender unifié
- **Entra ID P2** (Identity Protection) et **Intune** pour l'identité et les appareils (IAM)  
- **Logic Apps** pour l'automatisation de la réponse
- **Defender Vulnerability Management** pour le cycle de gestion des vulnérabilités

---

## 🖥️ Architecture

![Architecture du lab : trois VM, le workspace Sentinel law-sc200 et le portail Defender unifié](images/architecture.png)

VMs :

- `CLOUD-W11` (VMware, local) : Windows 11 Enterprise, onboardé dans **Defender for Endpoint** et enrôlé dans **Intune**
- `CLOUD-WINDOWS` (Azure) : Windows Server, security events vers Sentinel via **AMA** et une **DCR**
- `CLOUD-UBUNTU` (Azure) : Ubuntu 24.04, Syslog vers Sentinel via **AMA** et une **DCR**

Sources connectées à Sentinel (`law-sc200`) :

- Entra ID (sign-in logs et audit logs), Azure Activity, threat intelligence (STIX)
- Incidents et alertes Defender XDR, synchronisés automatiquement
- Une table custom (`LabCustomEvents_CL`) créée pour la Logs Ingestion API (DCE + DCR)

Comptes SOC, selon le principe du moindre privilège :

| Compte | Rôle SOC | Rôle Entra (Defender XDR) | Rôles Azure (Sentinel) |
|--------|----------|---------------------------|------------------------|
| `soc.reader` | Observateur | Security Reader | Microsoft Sentinel Reader |
| `soc.analyst` | Triage et réponse | Security Operator | Microsoft Sentinel Responder + Playbook Operator |
| `soc.engineer` | Règles, connecteurs, workbooks, playbooks | Security Administrator | Microsoft Sentinel Contributor + Logic App Contributor |
| `soc.target1`, `soc.target2` | Utilisateurs ciblés par les tests | Aucun | Aucun |

---

## ⚡ Workflow opérationnel

1. **Ingestion** : AMA et DCR (Windows, Syslog), Azure Policy (Azure Activity), Entra ID, threat intelligence, table custom
2. **Détection** : analytics rules KQL (scheduled, NRT, watchlist), custom detection Defender XDR, UEBA, anomalies, TI map, couverture MITRE ATT&CK
3. **Automatisation** : automation rules de triage et playbook Logic Apps en managed identity
4. **Investigation et réponse** : attack story, device timeline, live response, investigation package, isolement, Identity Protection
5. **Threat hunting** : advanced hunting, hunting queries Sentinel, bookmarks
6. **Gestion des vulnérabilités** : inventaire, priorisation des CVE en KQL, remédiation via Intune, vérification

---

## 🔎 Détections

| Règle | Type | MITRE ATT&CK | Test | Requête | Preuve |
|-------|------|--------------|------|---------|--------|
| SR - MULTIPLE FAILED LOGONS | Scheduled rule (5 min) | [T1110](https://attack.mitre.org/techniques/T1110/) | 6+ mots de passe RDP erronés | [KQL](kql/detections/SR-MULTIPLE-FAILED-LOGONS.kql) | [Alerte](images/detections/SR-MULTIPLE-FAILED-LOGONS.png) |
| NRT - USER ACC CREATED | NRT rule | [T1136](https://attack.mitre.org/techniques/T1136/) | `net user … /add` | [KQL](kql/detections/NRT-USER-ACC-CREATED.kql) | [Alerte](images/detections/NRT-USER-ACC-CREATED.png) |
| SR - VIP SIGN-IN FAILURES | Scheduled rule + watchlist | [T1110](https://attack.mitre.org/techniques/T1110/) | 3+ échecs pour un compte VIP | [KQL](kql/detections/SR-VIP-SIGNIN-FAILURES.kql) | [Alerte](images/detections/SR-VIP-SIGNIN-FAILURES.png) |
| CD - ENCODED POWERSHELL | Custom detection (Defender XDR) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | `powershell -enc …` | [KQL](kql/detections/CD-ENCODED-POWERSHELL.kql) | [Alerte](images/detections/CD-ENCODED-POWERSHELL.png) |
| TI map IP entity to SigninLogs | Template (threat intelligence) | N/A (IOC) | Connexion depuis une IP signalée | Template Content hub | [Alerte](images/detections/TI-MAP-SIGNINLOGS.png) |
| Anomalous RDP Login Detection | ML behavior analytics | [T1078](https://attack.mitre.org/techniques/T1078/) | RDP depuis une IP jamais vue, après 10 jours d'apprentissage | Template Microsoft | — |

Chaque fichier `.kql` commence par un en-tête : MITRE, planification, seuil, entités, test réalisé, résultat observé et limites connues.

---

## 📊 Résultats

- ✅ 6 sources ingérées dans Sentinel (Windows Security Events, Syslog, Azure Activity, Entra ID, threat intelligence, Defender XDR), chacune validée par requête, plus une table custom pour la Logs Ingestion API
- ✅ 4 détections KQL créées et testées contre des attaques simulées, chacune mappée à MITRE ATT&CK
- ✅ UEBA activé (sign-ins, audit, security events, Azure Activity, `DeviceLogonEvents`) et une anomaly rule dupliquée puis ajustée en Flighting
- ✅ Anomalie ML *Anomalous local account creation* (T1136) levée par le même test que la règle NRT : sans alerte ni incident, dans la table `Anomalies`, au calcul quotidien suivant ([preuve](images/sentinel/anomaly-local-account-creation.png))
- ✅ TI map : alerte sur une connexion depuis une IP signalée par un indicateur de test
- ✅ Automatisation : tags, assignation, statut, tâches et commentaire du playbook appliqués automatiquement à la création d'un incident
- ✅ Identity Protection : connexion Tor détectée (Anonymous IP address) quelques minutes après une connexion légitime, confirmée compromise puis remédiée
- ✅ Investigation complète des incidents : live response, investigation package, isolement et libération de `CLOUD-W11`, classification et clôture
- ✅ Threat hunting : advanced hunting et hunting queries Sentinel, avec bookmark rattaché à un incident
- ✅ Gestion des vulnérabilités : CVE introduite, priorisée, remédiée via Intune et vérifiée par la baisse de l'exposure score

---

## 🧠 Ce que j'ai appris

- **Un connecteur « connecté » ne prouve rien, des lignes dans la table oui.** `AzureActivity` est resté vide pendant des jours sans qu'aucun écran ne le signale : la policy avait été assignée sans remediation task. C'est UEBA qui l'a révélé : la source y était marquée not ingested. Depuis, chaque source est validée par `Table | take 5`.
- **Un playbook peut échouer en silence.** Les tags apparaissaient, mais pas le commentaire : erreur 403, parce que la managed identity du playbook n'avait pas le rôle Microsoft Sentinel Responder. Trois identités sont en jeu (la personne, le compte de service Sentinel, la managed identity), chacune avec son propre rôle.
- **Les tables Defender ne sont pas dans le workspace.** `DeviceNetworkEvents` est vide dans Log Analytics alors qu'Advanced hunting en contient beaucoup. D'où la custom detection Defender XDR pour PowerShell encodé, et le template TI map sur `SigninLogs` plutôt que sur `DeviceNetworkEvents`.
- **Les échecs RDP avec NLA sont des logons de type 3, pas 10.** Filtrer les 4625 sur le type 10 aurait masqué mes propres tests de brute force.
- **Quelques mots de passe erronés ne créent pas de risque.** 8 échecs n'ont rien levé dans Identity Protection. 1 connexion Tor, oui, mais seulement une fois la licence Entra ID P2 assignée à l'utilisateur ciblé.
- **Limite connue :** `SR - MULTIPLE FAILED LOGONS` détecte le brute force (un compte, plusieurs mots de passe) mais pas le password spray (plusieurs comptes). Une règle groupée par IP source est la prochaine étape.

---

## 📂 Documentation

👉 [Guide détaillé des phases](GUIDE.md)
👉 [Requêtes KQL](kql/) : détections, hunting et workbook
👉 [Automatisation](automation/README.md) : playbook et automation rules
👉 [Rapports d'incident](rapports/README.md)

```
SOC-SC200-Lab/
├── GUIDE.md                 # phases 0 à 6, étape par étape
├── kql/
│   ├── detections/          # analytics rules et custom detection, avec en-têtes
│   ├── hunting/             # advanced hunting et vulnérabilités
│   └── workbook/            # requêtes du workbook Lab SOC overview
├── watchlists/LabVIPs.csv   # watchlist de la règle VIP
├── automation/              # playbook PB-INCIDENT-COMMENT et automation rules
├── rapports/                # rapports d'incident
└── images/                  # captures d'écran (données sensibles floutées)
```

---

## ⚠️ Avertissement

Ce projet est un lab pédagogique destiné à l'apprentissage et à la préparation de la SC-200.

- Les attaques sont simulées sur des VM et des comptes de test, jamais sur un poste personnel ou un environnement de production.
- Les noms de tenant, adresses IP publiques et identifiants réels ont été retirés ou floutés.
- Les configurations sont simplifiées à des fins d'étude et ne constituent pas une solution prête pour la production.

---

*Dernière mise à jour : octobre 2026*

