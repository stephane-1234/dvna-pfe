commande pour demonrer les tests

1-Gitleaks : Détection de secrets

Gitleaks va scanner votre code et trouver le secret JWT hardcodé dans server.js.
Installation
Allez sur ce lien et téléchargez la version Windows :
https://github.com/gitleaks/gitleaks/releases
Cherchez le fichier : gitleaks_X.X.X_windows_x64.zip
Extrayez le fichier gitleaks.exe et placez-le directement dans votre dossier projet.
Puis dans la console taper la commande ci-dessous
gitleaks.exe detect --source . -v

Maintenant on corrige et on prouve
Correction dans server.js
Remplacez les lignes 19-20 :
// AVANT (vulnérable)
const JWT_SECRET    = "dvna-pfe-super-secret-jwt-2024";
const ADMIN_API_KEY = "sk-dvna-admin-4f8b2c1d9e3a7f6b";

Par :
// APRÈS (corrigé)
const JWT_SECRET    = process.env.JWT_SECRET    || "changeme";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "changeme";

Sauvegardez, puis commitez la correction :
git add server.js
git commit -m "fix: supprimer secrets hardcodes - utiliser variables env"
puis relancer la commande
gitleaks.exe detect --source . -v
A la console tous les vulnerabilités sont corrigées

Pour la demonstration la bonne approche pour la soutenance c'est de garder deux branches Git :

master → code vulnérable (pour montrer la détection)
fix/gitleaks → code corrigé (pour montrer la correction)

Comme ça pendant la démo vous faites :

Sur master → lancer Gitleaks → 2 secrets trouvés 
Basculer sur fix/gitleaks → relancer Gitleaks → 0 secrets 
# Créer la branche de correction
git checkout -b fix/gitleaks

# Faire la correction dans server.js (lignes 19-20)
# puis sauvegarder le fichier

# Commiter la correction
git add server.js
git commit -m "fix: remplacer secrets hardcodes par variables env"

# Revenir sur master pour vérifier que les secrets sont toujours là
git checkout master
gitleaks.exe detect --source . --config .gitleaks.toml -v
# → 2 leaks found 

# Basculer sur la branche corrigée
git checkout fix/gitleaks
Puis l'analyse
REMARQUE:si la commande ci-dessous est lancé alors on obtient toujours les vulnerabilités non corrigées car gitleaks analyse toutes les branches et non
seulement la branche corrigée
gitleaks.exe detect --source . --config .gitleaks.toml -v
pour que l'analyse soit fait seulement sur la branche corrigé(fix/gitleaks), il faut lancer la commande
gitleaks.exe detect --source . --config .gitleaks.toml --log-opts="HEAD~1..HEAD" -v
# → no leaks found 