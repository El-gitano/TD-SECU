#!/usr/bin/python3.2
# -*-coding:Utf-8 -*

"""
	Liens vers la doc. de la librairie
	
	getRandomInteger 	->	https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.number-module.html#getRandomInteger 
	getRandomRange 		->	https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.number-module.html#getRandomRange
	getPrime			->	https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.number-module.html#getPrime
	bytes_to_long		-> 	https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.number-module.html#bytes_to_long
	SHA512				->	https://www.dlitz.net/software/pycrypto/api/current/Crypto.Hash.SHA512.SHA512Hash-class.html
"""
try:

	from Crypto.Util import number
	from Crypto.Hash import SHA512

except ImportError:

	print "Le package contenant les outils cryptographiques est manquant, lire le README svp"


"""
	Génère les paramètres nécessaires pour l'utilisation des fonctions liées à DSA
	Retourne un tuple de nombres (p, q, y, g)
"""
def DSAGenParameter():

	print "Génération des paramètres"
	
	# On génère Q
	print "Génération de Q"
	q = number.getPrime(160)
	print "Q généré"
	
	# On génère P
	print "Génération de P"
	while True:
	
		r = number.getRandomInteger(480)
		p = (q*r)+1
		
		if number.isPrime(p):
			break
	print "P généré"
	
	# On génère G
	print "Génération de G"
	while True:
	
		y = number.getRandomRange(0, p)
		g = pow(y, (p-1)/q, p)
		
		if g != 1:
			break
	print "G généré"
	
	print "Paramètres générés"
	
	return p, q, y, g

"""
	Génère un paire de clé à utiliser pour signer/vérifier un message
	L'ensemble des paramètres doit être renseigné
	
		- q doit être un diviseur de (p-1)
		- g doit être égal à y^( (p-1)/q ) % p
		
	Retourne le tuple (pk, sk) représentant respectivement la clé publique et la clé secrète
"""
def DSAGenKey(p, q, y, g):

	# Préconditions
	if q == None or p == None or g == None or y == None:
	
		raise ValueError("Les paramètres ne sont pas tous renseignés")
	
	if ((p-1) % q) != 0:
	
		raise ValueError("Les paramètres p et q ne sont pas corrects")
	
	if g != pow(y, (p-1)/q, p):
	
		raise ValueError("Les paramètres y et g ne sont pas corrects")

	# Traitement
	print "Génération d'une paire de clés"

	sk = number.getRandomRange(0, q)
	pk = pow(g, sk, p)
	
	print "Génération des clés terminée"
	return pk, sk

"""
	Signe un message à l'aide d'une clé secrète
	L'ensemble des paramètres doit être renseigné
	
	- myMessage le message à signer
	- sk la clé secrète pour générer la signature
	- p, q et g les paramètres ayant servi à générer la clé secrète
	
	Retour un tuple (r, s) représentant la signature du message
"""	
def DSAsign(myMessage, p, q, g, sk):

	# Préconditions
	if myMessage == None or sk == None or p == None or q == None or g == None:
	
		raise ValueError("Les paramètres ne sont pas tous renseignés")
	
	# Traitement
	print "Signature d'un message"
	
	sha512 = SHA512.new()
	sha512.update(myMessage)
	hashMessage = number.bytes_to_long(sha512.digest())

	k = number.getRandomRange(0, q)		 
	r = pow(g, k, p) % q
	s = ((hashMessage+(sk*r)) * number.inverse(k, q)) % q
	
	print "Message signé"
	return r, s

"""
	Vérifie la signature d'un message
	L'ensemble des paramètres doit être renseigné.
	
	- pk 			La clé publique
	- p, q et g 	Les paramètres ayant servi à générer la clé publique
						q doit être un diviseur de (p-1)
	- signature 	Un tuple contenant les deux éléments de la signature
	- message		Le message à vérifier
	- hashMessage	Le hash du message
	
	Retourne True ou False selon la vérification de la signature
"""
def DSAverif(p, q, g, pk, message, messageHash, signature):

	# Préconditions
	if p == None or p == None or pk == None or g == None or message == None or messageHash == None or signature == None:
	
		raise ValueError("L'ensemble des paramètres n'est pas renseigné")
		
	if (p-1)%q != 0:
	
		raise ValueError("Erreur dans le renseignement des nombres p et q")
	
	# Traitement
	r = signature[0]
	s = signature[1]
	
	invS = number.inverse(s, q)  # Modulo inverse de S
	 
	a = (messageHash * invS) % q
	b = (r * invS) % q
	
	comp = ((pow(g, a, p) * pow(pk, b, p)) % p) % q
	
	if comp == r:
	 
	 	return True
	 	
	else:
	 
		return False
	
if __name__ == '__main__':
	 
	# Implémentation de DSA + Vérification
	print "Question n°2\nTest de l'implémentation de DSA :\n"

	myMessage = b"123456"
	sha512 = SHA512.new()
	sha512.update(myMessage)
	messageHash = number.bytes_to_long(sha512.digest())
	
	p, q, y, g = DSAGenParameter()
	pk, sk = DSAGenKey(p, q, y, g)
	r, s = DSAsign(myMessage, p, q, g, sk)
	
	print "\nVérification de la signature avec une clé correcte : {0}".format(DSAverif(p, q, g, pk, myMessage, messageHash, (r, s)))
	print "Vérification de la signature avec une clé incorrecte : {0}".format(DSAverif(p, q, g, 123, myMessage, messageHash, (r, s)))
	
	# Vérifications pour les exemples du TP
	print "\nVérification des signatures du TP\n"
	
	p = 15811267
	q = 541
	g = 557069
	pk = 12657825
	
	print "a.Résultat de la vérification : {0}".format(DSAverif(p, q, g, pk, 52, 5836403135864276661, (344, 107) ))
	print "b.Résultat de la vérification : {0}\n".format(DSAverif(p, q, g, pk, 19, 8654798746728582722, (374, 241) ))
