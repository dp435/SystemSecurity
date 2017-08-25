from Crypto.PublicKey import RSA
from Crypto import Random
import os


def generate_keys(user):
    try: 
        os.makedirs("public")
    except OSError:
        if not os.path.isdir("public"):
            raise

    try: 
        os.makedirs(user)
    except OSError:
        if not os.path.isdir(user):
            raise

    key_length = 7680
    key = RSA.generate(key_length, Random.new().read)

    public_key = key.publickey().exportKey('DER')
    public_dir = open('public/' + user + '_public.der','wb')
    public_dir.write(public_key)
    public_dir.close()

    private_key = key.exportKey('DER')
    private_dir = open(user + '/' + user + '_private.der','wb')
    private_dir.write(private_key)
    private_dir.close()

if __name__ == "__main__":
    generate_keys('Alice')
    print("Key generation for Alice successful.")
    generate_keys('Bob')
    print("Key generation for Bob successful.")
