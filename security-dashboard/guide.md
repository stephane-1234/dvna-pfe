Demarrer avec Ollama
Aucune cle API, aucune connexion internet requise
1-Installer Ollama
Telechargez et installez Ollama sur Windows.
https://ollama.com/download

2-Telecharger le modele
Ouvrez un terminal et telechargez le modele recommande (9 GB, une seule fois).
ollama pull qwen2.5-coder:14b
3-Démarrer le serveur Ollama : ollama serve
4-Verifier qu'Ollama tourne
Ollama demarre automatiquement au lancement de Windows. Verifiez avec :
curl http://localhost:11434/api/tags
Si vous voyez la liste des modeles : Ollama est pret.
Message "bind: address already in use" = Ollama tourne deja, c'est normal.
5-Demarrer le serveur dashboard
Dans le dossier security-dashboard :
node report-server.js
6-Ouvrir le dashboard
Dans le navigateur, ouvrez :
http://localhost:3500
Selectionnez l'onglet Ollama (local), choisissez qwen2.5-coder:14b et cliquez Tester la connexion.

Demarrer avec l'API Claude
Meilleure qualite d'analyse, necessite internet
1-Creer un compte Anthropic
Allez sur la console Anthropic et creez un compte gratuit.
https://console.anthropic.com
2-Acheter les credits
Cliquez sur Billing puis Buy credits. Le minimum est 5$ — suffisant pour ~250 analyses completes.
Sans credits, l'API retourne une erreur 403.
3-Generer une cle API
Allez dans API Keys → Create key. Donnez un nom ex: dvna-pfe.
Copiez la cle immediatement — elle ne sera plus visible apres fermeture.
4-Demarrer le serveur dashboard
Dans le dossier security-dashboard :
node report-server.js
5-Ouvrir le dashboard
Dans le navigateur, ouvrez :
http://localhost:3500
Selectionnez l'onglet Claude API, collez votre cle sk-ant-api03-... et lancez l'analyse.
1 pipeline complet = environ 0.02$ de credits utilises.