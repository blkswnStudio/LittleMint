from secret_connection import SecretConnection

if "__main__" == __name__:
    host = "162.19.234.220" # 213.136.69.68
    port = 26656

    sc = SecretConnection(host, port)
    sc.connect()