# filter_dns
Fluent-bit C Plugin : reverse DNS lookup of IP v4 addresses

# Fluent Bit Filter Plugin: DNS Lookup avec TTL

[FILTER]
    Name        dnslookup
    Match       *
    cache_ttl   300



🧱 Ajoute dans plugins/filter/CMakeLists.txt

FLB_PLUGIN(filter_dnslookup "DNS Lookup Filter" filter_dnslookup.c)


## Construire l'environnement de développement sur son poste de travail

Aller dans le répertoire devcontainer

recopier une clef publique SSH (exemple : cp ~/.ssh/id_rsa_dev.pub authorized_keys)

l'image créé par défaut un compte david : pensez à lui substituer le compte utilisateur de votre choix (remplacer david par xxx dans le compose.yaml et le Dockerfile)

créé l'image (elle inclut la compilation de Fluent-bit...) 
```
$ docker compose up --build -d
``̀

Un conteneur est maintenant disponible pour développer

Si vous utilisez Codium, vous pouvez utiliser le plugin open remote ssh avec le paramétrage suivant :

créer le fichier ~/.ssh/config
```
Host fluentbit-container
    HostName 127.0.0.1
    User david
    Port 2022
```

et bonne chance avec votre plugin