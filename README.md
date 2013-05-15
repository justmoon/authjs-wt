# Auth.js

Auth.js is a JavaScript implementation for peer-assisted key derivation.

# Background

## Key Derivation vs Login

Key derivation is a method for deriving encryption keys from relatively weak
passwords. Derivation algorithms are intentionally expensive and thereby slow
down a brute-forcing attacker by some factor.

However, there is a limit to how strong of a derivation function we can use.
Some users may want to use devices that don't have a lot of computational power
or for which an efficient implementation of the derivation function is not
available.

Empirically we found that there is such a large gap between the minimum device
we wish to support and the maximum computational power that we assume an
attacker might have, that pure offline key derivation is not sufficient.

By comparison, online logins have far more powerful options for defending
against brute force attacks. Some high-security servers will lock an account
entirely after a fixed number of login attempts. Login systems also have the
benefit that ongoing attacks are detectable, which allows the operators of a
login system to actively defend against it.

## A compromise

Auth.js implements a form of online or active key derivation. We lose the
benefits of being able to perform the key derivation entirely offline - but
that's the point, we want the attacker to lose those "benefits".

But unlike with a regular login system users still retain much of their
independence. By using blind signing, we guarantee that the server does not gain
any information about the user's password - information-theoretic security.

At the same time, most measures that can be taken by traditional login system
are still available to active key derivation systems such as rate limiting,
secondary means of authentication, etc.

## Failure tolerance

One of the main benefits of doing key derivation offline, is that we do not need
to rely on any server being operational in order to derive our keys. In an
online derivation system, we do.

To mitigate this downside somewhat and also to strengthen security, we can use a
threshold version of active key derivation called peer-assisted key derivation.
In this model we create a threshold shared secret across the derived secrets
of multiple  nodes. That way we introduce fault tolerance and we also remove the
ability of any individual node to perform offline attacks against us.

## Read more

* links here...

# Status

Auth.js is in the early stages of development. So far it implements a
minimalistic version of the server functionality and a simple test page to
demonstrate it.

# Setup

``` sh
# Clone repository
git clone [repo url] authjs
cd authjs

# Install dependencies
npm install

# Initialize the configuration
cp config-example.js config.js

# Generate a key
npm run gen
```

# Running

``` sh
node app
```

You can then view the demo page at http://localhost:3000/

# Credits

Auth.js (c) 2013 Stefan Thomas  
Released under MIT license  

JSBN (c) 2003-2005 Tom Wu  
Released under BSD license  
http://www-cs-students.stanford.edu/~tjw/jsbn/

// TODO: Remaining credits




















