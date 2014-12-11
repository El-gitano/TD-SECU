#!/usr/bin/python3.2
# -*-coding:Utf-8 -*

#Librairie utilisée pour la génération des nombres premiers
try:

	from Crypto.Util import number
	from Crypto.Hash import SHA512

except ImportError:

	print "Le package contenant les outils cryptographiques est manquant, lire le README svp"


"""
	Génère les paramètres nécessaires pour l'utilisation des fonctions liées à DSA
	Retourne un tuple de nombres (q, p, y, g)
"""
def DSAGenParameter():

	print "Génération des paramètres"
	
	q = number.getPrime(160)
	
	#On génère P
	while True:
	
		p = number.getPrime(512)
		
		if (p-1)%q == 0:
			break
	
	#On génère G
	while True:
	
		y = getRandomInteger(128)
		
		if y >= p:
			continue
			
		g = pow(y, (p-1)/q, p)
		
		if g != 1:
			break
	
	print "Paramètres :\n\n\tQ: {0}\n\tP: {1}\n\tY: {2}\n\tG: {3}".format(q, p, y, g)
	
	return q, p, y, g

"""
	Génère un paire de clé à utiliser pour signer/vérifier un message
	L'ensemble des paramètres doit être renseigné
	
		- q doit être un diviseur de (p-1)
		- g doit être égal à y^( (p-1)/q )
		
	Retourne le tuple (pk, sk) représentant respectivement la clé publique et la clé secrète
"""
def DSAGenKey(q, p, y, g):

	#Préconditions
	if q == None or p == None or g == None or y == None:
	
		raise ValueError("Les paramètres ne sont pas tous renseignés")
	
	if (p-1) % q != 0:
	
		raise ValueError("Les paramètres p et q ne sont pas corrects")
	
	if g != pow(y, (p-1)/q):
	
		raise ValueError("Les paramètres y et g ne sont pas corrects")
	
	print "Génération d'une paire de clé"
	
	#Traitement
	while True:
	
		sk = getRandomInteger(128)
		
		if sk < q:
			break;
	
	pk = pow(g, sk, p)
	
	print "Clé publique : {0}\nClé privée : {1}\n".format(pk, sk)
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

	#Préconditions
	if myMessage == None or sk == None or p == None or q == None or g == None:
	
		raise ValueError("Les paramètres ne sont pas tous renseignés")
	
	#Traitement
	resHash = SHA512.new().update(myMessage).hex_digest()
	
	#Génération de la clé éphémère K
	while True:
	
		k = getRandomInteger(128)
		if k<q:
		 	break
		 
	r = pow(g, k, p)%q
	s = (resHash+(sk*r))/k) % q
	
	print "Signature du message {0}, {1}".format(r, s)
	
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

	#Préconditions
	if p == None or p == None or pk == None or g == None or message == None or messageHash == None or signature == None):
	
		raise ValueError("L'ensemble des paramètres n'est pas renseigné")
		
	if (p-1)%q != 0:
	
		raise ValueError("Erreur dans le renseignement des nombres p et q")
	
	 #Traitement
	 
	
if __name__ == '__main__':

	print "Question n°2\n"
	print "a.{0}".format(DSAverif(15811267, 541, 557069, 12657825, 52, 5836403135864276661, (344, 107) ))
	print "b.{0}".format(DSAverif(15811267, 541, 557069, 12657825, 19, 8654798746728582722, (374, 241) ))
	

