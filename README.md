#The Cryptopals
Simply working through the [Cryptopals Crypto Challenges](http://cryptopals.com), using Python 3.  Thanks to @tqbf, @spdevlin, @iamalexalright, @marcinw, and the rest of the involved crypto gurus for making these crypto challenges into a thing.

#Setup Development Environment
First, we will clone the repository into a local directory.  Then we will set up the Python3 virtualenv for development and testing.

```bash
git clone https://github.com/bruteforce1/cryptopals.git
cd cryptopals
sudo pip install virtualenv
virtualenv -p python3 venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r pyreqs.txt
```

