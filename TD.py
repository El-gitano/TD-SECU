#!/usr/bin/python3.2
# -*-coding:Utf-8 -*

"""
Signe le message passé en parèmètre à partir de l'ensemble des autres paramètres
L'ensemble des paramètres doit être renseigné et positif
Retourn un tuple (r, s) représentant la signature du message
"""
def DSAsign(message, p, q, g, sk, pk):

	k = int(random.random()*q)%q
	r = pow(g, k, p) % q
	s = ((h+(sk*r))/k) % q
	
	return r, s	

"""
Vérifie la signature d'un message
L'ensemble des paramètres doit être renseigné
Retourne True ou False selon la vérification de la signature
"""
def DSAverif(message, signature):

	
	
if __name__ == '__main__':

	print "Question n°2\n"
	#DSAverif()
	#DSAverif()
