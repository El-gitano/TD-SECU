#!/usr/bin/python3.2
# -*-coding:Utf-8 -*


from Crypto.Util import number

""" 

	Test de la librairie Crypto
	Un premier aléatoire de 512 bits sera-t-il toujours plus petit qu'un premier aléatoire de 511 bits ?
	EDIT : Retourne faux
	
"""

if __name__ == '__main__':

	#On teste un grand nombre de fois pour être sûr
	for i in range(20000):
	
		a = number.getRandomInteger(512)
		b = number.getRandomInteger(511)
		
		if a<b:
		
			print "FAUX !", i
			break;
