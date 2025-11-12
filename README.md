# Sécurité des applications

Cours: INFO001
Type: TP
Dernière modification: 12 novembre 2025 16:39
Semestre: S9

# Cryptographie appliquée : TLS/SSL PKI

Binôme : Léo Dupraz-Roget, Paul Coulmeau

Machine Paul Coulmeau : 192.168.170.158

# Préparation

### Question 1

Chiffrement d’un message par RSA : $C \equiv M^e \mod n$

Pour déchiffrer il faut : $M \equiv C^d \mod n$

- M : entier naturel
- n = message

### Question 2

Deux agents  (*Alice et Bob)* peuvent se mettre d'accord sur un nombre (qu'ils peuvent utiliser comme clé pour chiffrer la conversation suivante) sans qu'un troisième agent puisse découvrir le nombre, même en ayant écouté tous leurs échanges.

### Question 3

- La signature
- La clé publique
- La clé privée NON ! NON ! NON
- Le sujet du certificat

# 4. Etude du chiffrement RSA

## 4.1 Génération de clés RSA

Pour générer une clé RSA il faut taper la commande :

`openssl genpkey -algorithm RSA -out rsa_keys.pem -pkeyopt rsa_keygen_bits:1024`

### Question 5

- n vaut 1024 bits
- Chiffrement d’un message par RSA : $C \equiv M^e \mod n$
- Pour déchiffrer il faut : $M \equiv C^d \mod n$
- Non il est connu de tous, mais la sécurité ne dépend pas de e, mais la difficulté de factoriser par q et p.

### Question 6

Chiffrer une clé publique n’est pas nécessaire, mais en revanche la clé privé oui car il serais alors possible de déchiffrer tous les messages.

### Question 7

L’encodage utilisé est sur la base 64 pour avoir un texte ASCII lisible. Et le format PEM est utilisé pour contenir le texte entre deux balises (Begin & End)

### Question 8

On retrouve bien la partie “Modulus” dans le fichier de la clé publique. On le sépare pour que plus tard on puisse le retrouver plus facilement, et pas mélanger la partie privé de la partie publique.

## 4.2 Chiffrement asymétrique

### Question 9

Pour chiffrer le message on doit utiliser la clé publique du destinataire.

### Commandes pour communiquer

Afin de récupérer la clé publique de mon voisin on peu faire :
`> curl -O [http://192.168.170.161/pub.duprazrl.pem](http://192.168.170.161/pub.duprazrl.pem)`

Pour récupérer ma clé publique faire :

 `> curl -O [http://192.168.170.158/pub.coulmeap.pem](http://192.168.170.158/pub.coulmeap.pem)`

### Pour déchiffrement

Quand on reçoit le fichier chiffré, on le déchiffre de cette manière :

`> openssl pkeyutl -decrypt -inkey rsa_keys_cyphered.pem -in cipher.leo.bin -out message_recieve.txt`

# 5 Analyse du contenu d'un certificat

## 5.1 En ligne de commandes openssl s_client

### Question 12

Affiche l’ensemble des certificats envoyés par le serveur:

- Certificat du serveur (depth=0)
- Certificat intermédiaire (depth=1)
- Certificat racine (depth=2)

### Question 13

`x509` est un format standard de certificat de clé publique.

On a comme sujet, la ligne :

```markdown
Issuer: C=NL, O=GEANT Vereniging, CN=GEANT OV RSA CA 4
...
Subject: C=FR, ST=Auvergne-Rhône-Alpes, O=Université Grenoble Alpes, CN=*.univ-grenoble-alpes.fr
```

| C | Pays (Country Name) |
| --- | --- |
| ST | Région de l’organisation (State or Province Name) |
| O | Nom de l’organisation (Organization Name) |
| CN | Le nom principal du certifact (Common Name) = nom de domaine |

### Question 14

Dans le certificat on a ces lignes :

```markdown
s:C = FR, ST = Auvergne-Rh\C3\B4ne-Alpes, O = Universit\C3\A9 Grenoble Alpes, CN = *.univgrenoble-alpes.fr
i:C = GB, ST = Greater Manchester, L = Salford, O = Sectigo Limited, CN = Sectigo RSA Organization
Validation Secure Server CA
```

| s | Le sujet, donc le propriétaire du certificat. | *.univgrenoble-alpes.fr |
| --- | --- | --- |
| i | L’émetteur, donc l’autorité de certification (CA) qui a signé et délivré ce certificat | Sectigo RSA Organization |

### Question 15

L’algorithme sha384 qui a été utilisé pour signer le certificat. 

Le certificat est valide du 18/12/2024 au 18/12/2025, soit 1 an.

Le CN contient : *.univ-grenoble-alpes.fr

Lien pointant : liste tous les autres noms de domaine ou machines pour lesquels le certificat est valide. 

Attribut qui contient les autres noms de machine pour lequel le certificat peut être utilisé : X509v3 Subject Alternative Name (SAN)

### Question 16

Dans le certificat il y a :
Issuer : l’émetteur du certificat, donc le certificat de [www.univ-grenoble-alpes.fr](http://www.univ-grenoble-alpes.fr/) a été signé par l’autorité GEANT OV RSA CA 4. Elle utilise sa clé privée RSA pour générer la signature.

Formule : $S = H(M)^{d_{CA}} \mod n_{CA}$ où $H(M)$ est le hash SHA-384 du certificat.

### Question 17

La clé publique présente dans ce certificat est une clé RSA de 4096 bits.

Le certificat a été signé par “CA GEANT OV RSA CA 4”

### Question 18

La certification précédente a été signé par “USERTrust RSA Certification Authority” (New Jersey) 

### Question 19

Le Subject et le Issuer sont identiques. Donc le certificat s’est signé lui-même car c’est une autorité de certification racine. Il ne dépend d’aucune autre autorité. Sa clé privée a été utilisée pour signer son propre certificat :

`Issuer: C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority`

# 6. Mise en place d'une PKI (Public Key Infrastructure)

## 6.2 Étude de la CA Racine (CN=Root Lorne)

### Question 20

le type et la taille de la clé : Clé EC (Elliptic Curve), 256bit

```bash
openssl x509 -in /home/camanager/ca/certs/ca.cert.pem -noout -text
```

la durée de validité : Du 1er novembre 2025 au 27 octobre 2045

Oui, car Issuer = Subject → c’est une autorité de certification racine

Voici la clé privé ainsi que la commande pour l’afficher :

```
**[camanager@root-ca-tp ca]$ openssl ec -in /home/camanager/ca/private/ca.key.pem -noout -text
read EC key
Enter pass phrase for /home/camanager/ca/private/ca.key.pem:
Private-Key: (256 bit)
priv:
    a0:de:af:51:d2:f3:ac:d4:a6:2f:da:c0:a9:69:3e:
    cf:b2:83:ef:cd:fa:31:f2:48:fc:63:50:16:dd:18:
    0e:90
pub:
    04:8f:be:64:f6:0d:ba:a8:9a:50:fa:24:39:4e:e4:
    70:ef:0d:ea:64:40:5b:60:31:40:3d:07:f5:26:34:
    15:d5:a0:97:cc:55:80:f2:3c:04:2d:47:42:5f:de:
    c6:b3:69:41:35:7e:0e:58:b9:ee:12:f1:97:4b:99:
    3d:77:25:04:a7
ASN1 OID: prime256v1
NIST CURVE: P-256**
```

## 6.3 Création d'une autorité de certification intermédiaire

### Question 21

Dans “dir” il faut mettre le chemin vers notre répertoire “ca” : `/home/etudiant/ca`

La clé privé sera stocké dans : `/home/etudiant/ca/private/intermediate.key.pem`

Le certificat sera enregistré sous ce nom : `/home/etudiant/ca/certs/intermediate.cert.pem`

### Question 22

La ligne de commande pour générer la clé RSA : 

```bash
openssl genrsa -aes128 -out private/ca-intermediate.key.pem 3072
```

Pour vérifier que la clé a bien été créé :

```bash
openssl rsa -in private/ca-intermediate.key.pem -check -noout
```

Avec un pass-code = *login*

### Question 23

Elle semble incongru car on n’a pas encore de certificat signé par une autorité à ce stade. La signature du CSR prouve que le demandeur est bien le propriétaire légitime de la clé publique incluse dans la requête.

```bash
openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
-days 3650 -notext -md sha256 -in csr/coulmeap.csr.pem \
-out certs/coulmeap.cert.pem
```

## 6.4 Création du certificat du serveur

### Question 24

Il est pertinent de générer la clé de chiffrement asymétrique directement sur la machine du serveur, c’est-à-dire sur la machine tls-serv car cette clé privée ne doit jamais quitter le serveur où elle sera utilisée car on augmente les risques d’interception ou de fuite pendant le transfert.

# Mise en place d’un reverse proxy

## 7. Mise en place de ssl

### Question 25

Pour des raisons pratiques, si les certificats intermédiaires venaient à changer il n’y aurais aucun problème. En outre on peut ajouter, révoquer ou remplacer des CAs intermédiaires sans devoir reconfigurer tous les clients.
