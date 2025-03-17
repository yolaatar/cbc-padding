import logging
from paddingoracle import BadPaddingException, PaddingOracle
from binascii import unhexlify, hexlify
from socket import socket, AF_INET, SOCK_STREAM

def pkcs7_unpad(data: bytes) -> bytes:
    """
    Retire le padding PKCS#7 d'un message.
    Si le padding est invalide, lève une ValueError.
    """
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Padding length out of range.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding detected!")
    return data[:-pad_len]

class MyPadBuster(PaddingOracle):
    """
    Implémentation alternative de l'attaque Padding Oracle.
    Se connecte au serveur et redéfinit la méthode oracle.
    """
    def __init__(self, host: str, port: int, max_retries: int = 5, **kwargs):
        super().__init__(max_retries=max_retries, **kwargs)
        self.log.setLevel(logging.DEBUG)
        self.host = host
        self.port = port
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.connect((self.host, self.port))
    
    def oracle(self, data, **kwargs):
        """
        Envoie le ciphertext (en bytes) au serveur après l'avoir converti en hexadécimal.
        Si le serveur répond par "Padding Error", lève BadPaddingException.
        Sinon, retourne True.
        """
        # Convertir data en hex majuscules
        data_hex = hexlify(data).upper()
        self.log.debug("Sending: %s", data_hex)
        # Envoi avec saut de ligne
        self.sock.sendall(data_hex + b'\n')
        resp = self.sock.recv(4096)
        resp_str = resp.decode('utf-8', errors='ignore')
        self.log.debug("Response: %s", resp_str)
        if "Padding Error" in resp_str:
            raise BadPaddingException
        return True

def main():
    logging.basicConfig(level=logging.DEBUG)
    # Paramètres du serveur et ciphertext cible
    host = "challenge01.root-me.org"
    port = 51014
    ciphertext_hex = "BC16542433100D9522DC3B6428D4FF5F7FC67B4994323C47ED09F185C3CE7A2E"
    ciphertext = unhexlify(ciphertext_hex)
    
    # Créer une instance de notre oracle personnalisé
    padbuster = MyPadBuster(host, port, max_retries=5)
    # Déchiffrer le ciphertext en précisant la taille du bloc (16 octets pour AES)
    decrypted = padbuster.decrypt(ciphertext, block_size=16)
    print("Decrypted value:", decrypted)
    
    # Retirer le padding pour obtenir le message final
    try:
        unpadded = pkcs7_unpad(bytes(decrypted))
    except ValueError as e:
        padbuster.log.error("Erreur lors du dépad : %s", e)
        unpadded = bytes(decrypted)
    
    # Afficher le résultat final sans padding (en UTF-8)
    final_result = unpadded.decode('utf-8', errors='replace')
    print("Final decrypted value (without padding):", final_result)

if __name__ == "__main__":
    main()
