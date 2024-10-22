import seal

def main():
    # Création d'un contexte SEAL avec des paramètres
    parms = seal.EncryptionParameters(seal.scheme_type.bfv)
    
    # Définir la taille du polynôme (8192 est généralement un bon compromis)
    parms.set_poly_modulus_degree(8192)
    
    # Définir le coefficient modulus (pour un chiffrement fort)
    parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(8192))

    # Utiliser un plain_modulus compatible avec le batching (premier de la forme 1 + 2^k)
    parms.set_plain_modulus(65537)

    # Créer le contexte SEAL
    context = seal.SEALContext(parms)
    
    # Générer des clés
    keygen = seal.KeyGenerator(context)
    
    # Utiliser la nouvelle méthode create_public_key()
    public_key = keygen.create_public_key()
    secret_key = keygen.secret_key()

    # Créer l'encodeur pour le schéma BFV (BatchEncoder)
    encoder = seal.BatchEncoder(context)

    # Encryptor et decryptor
    encryptor = seal.Encryptor(context, public_key)
    decryptor = seal.Decryptor(context, secret_key)

    # Nombre à encoder
    number = 12345
    print(f"Chiffrement du nombre : {number}")
    
    # Encodage du nombre sous forme de tableau
    encoded = encoder.encode([number])

    # Chiffrement
    encrypted = encryptor.encrypt(encoded)
    print(f"Texte chiffré : {encrypted}")

    # Déchiffrement
    decrypted = seal.Plaintext()
    decryptor.decrypt(encrypted, decrypted)

    # Décodage
    decoded = encoder.decode(decrypted)
    print(f"Nombre déchiffré : {decoded[0]}")

if __name__ == "__main__":
    main()