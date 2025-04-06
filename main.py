import argparse
import os
import pickle
from src.sphincs import spx_keygen, spx_sign, spx_verify
from src.parameters import get_parameters

def compute_file_hash(file_path):
    """Вычисление SHA-256 хэша файла."""
    import hashlib
    blake2b = hashlib.blake2b()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            blake2b.update(chunk)
    return blake2b.digest()

def main():
    parser = argparse.ArgumentParser(description="Консольный инструмент для работы с SPHINCS+")
    parser.add_argument("--instance", type=str, default="256f", choices=["128s", "128f", "192s", "192f", "256s", "256f"],
                        help="Набор параметров SPHINCS+ (по умолчанию: 256f)")
    
    parser.add_argument("--gen-keys", action="store_true", help="Сгенерировать пару ключей")
    parser.add_argument("--sk-out", type=str, help="Путь для сохранения секретного ключа")
    parser.add_argument("--pk-out", type=str, help="Путь для сохранения открытого ключа")

    parser.add_argument("--sign", type=str, help="Подписать сообщение (строка или путь к файлу)")
    parser.add_argument("--sk", type=str, help="Путь к файлу секретного ключа для подписи")
    parser.add_argument("--sig-out", type=str, help="Путь для сохранения подписи")
    parser.add_argument("--from-file", action="store_true", help="Указывает, что --sign это путь к файлу, а не строка")

    parser.add_argument("--verify", type=str, help="Проверить сообщение (строка или путь к файлу)")
    parser.add_argument("--pk", type=str, help="Путь к файлу открытого ключа для проверки")
    parser.add_argument("--sig", type=str, help="Путь к файлу подписи для проверки")

    args = parser.parse_args()

    params = get_parameters(args.instance)
    print(f"Используется набор параметров: {args.instance} -> {params}")

    if args.gen_keys:
        sk, pk = spx_keygen(params=params)
        print("Секретный ключ:", [x.hex()[:16] + "..." for x in sk])
        print("Открытый ключ:", [x.hex()[:16] + "..." for x in pk])
        
        if args.sk_out:
            with open(args.sk_out, 'wb') as f:
                pickle.dump(sk, f)
            print(f"Секретный ключ сохранён в: {args.sk_out}")
        if args.pk_out:
            with open(args.pk_out, 'wb') as f:
                pickle.dump(pk, f)
            print(f"Открытый ключ сохранён в: {args.pk_out}")
        return

    if args.sign:
        if not args.sk:
            print("Ошибка: Укажите путь к секретному ключу (--sk) для подписи!")
            return
        
        with open(args.sk, 'rb') as f:
            sk = pickle.load(f)
        
        if args.from_file:
            if not os.path.exists(args.sign):
                print(f"Ошибка: Файл {args.sign} не найден!")
                return
            message = compute_file_hash(args.sign)
            print(f"Хэш файла {args.sign}: {message.hex()[:16]}...")
        else:
            message = args.sign.encode('utf-8')
            print(f"Сообщение: {args.sign}")

        signature = spx_sign(message, sk, params=params)
        print(f"Длина подписи: {sum(len(x) if isinstance(x, bytes) else sum(len(y) for y in x) for x in signature)} байт")
        print(f"Компоненты подписи: {[len(x) if isinstance(x, bytes) else len(x) for x in signature]}")

        if args.sig_out:
            sig_data = {"instance": args.instance, "signature": signature}
            with open(args.sig_out, 'wb') as f:
                pickle.dump(sig_data, f)
            print(f"Подпись сохранена в: {args.sig_out}")
        return

    if args.verify:
        if not args.pk:
            print("Ошибка: Укажите путь к открытому ключу (--pk) для проверки!")
            return
        if not args.sig:
            print("Ошибка: Укажите путь к файлу подписи (--sig) для проверки!")
            return
        
        with open(args.pk, 'rb') as f:
            pk = pickle.load(f)
        with open(args.sig, 'rb') as f:
            sig_data = pickle.load(f)
        
        if isinstance(sig_data, dict) and "instance" in sig_data and "signature" in sig_data:
            loaded_instance = sig_data["instance"]
            signature = sig_data["signature"]
            if loaded_instance != args.instance:
                print(f"Предупреждение: Набор параметров подписи ({loaded_instance}) отличается от указанного ({args.instance}). Используется {loaded_instance}.")
                params = get_parameters(loaded_instance)
        else:
            signature = sig_data
            print("Предупреждение: Файл подписи не содержит информацию о наборе параметров. Используется текущий:", args.instance)

        if args.from_file:
            if not os.path.exists(args.verify):
                print(f"Ошибка: Файл {args.verify} не найден!")
                return
            message = compute_file_hash(args.verify)
            print(f"Хэш файла {args.verify}: {message.hex()[:16]}...")
        else:
            message = args.verify.encode('utf-8')
            print(f"Сообщение: {args.verify}")

        try:
            result = spx_verify(message, signature, pk, params=params)
            print(f"Результат проверки: {'Подпись верна' if result else 'Подпись неверна'}")
        except Exception as e:
            print(f"Ошибка проверки: {str(e)}")
        return

    parser.print_help()

if __name__ == "__main__":
    main()