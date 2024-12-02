from secret_connection import SecretConnection


def handler(sc: SecretConnection):
    while True:
        message = sc.read()
        print(message)




if "__main__" == __name__:
    host = "213.136.69.68" # 213.136.69.68
    port = 26656

    sc = SecretConnection(host, port)
    sc.connect()

    handler(sc)