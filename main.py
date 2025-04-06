from src.sphincs import spx_keygen, spx_sign, spx_verify

sk, pk = spx_keygen()

# Тестовое сообщение
message = b"Hello, SPHINCS+!"

# Подпись
signature = spx_sign(message, sk)

# Верификация
result = spx_verify(message, signature, pk)

# Вывод результатов
print("Secret key:", [x.hex() for x in sk])  # SK — список байтовых строк
print("Public key:", [x.hex() for x in pk])  # PK — список байтовых строк
print("Signature length:", len(signature))  # Длина подписи в элементах
print("Verification result:", result)