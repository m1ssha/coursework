import time
import os
import math
from tabulate import tabulate
from openpyxl import Workbook
from src.sphincs import spx_keygen, spx_sign, spx_verify
from src.parameters import get_parameters

SIZE_FILE = 1024 * 1024 * 1

def generate_test_file(size=SIZE_FILE):
    file_path = "test_file.bin"
    with open(file_path, "wb") as f:
        f.write(os.urandom(size))
    with open(file_path, "rb") as f:
        data = f.read()
    os.remove(file_path)
    return data

def measure_times(instance):
    """Измеряет время операций SPHINCS+ для файла 1 МБ и возвращает результаты с параметрами."""
    params = get_parameters(instance)
    message = generate_test_file()
    
    start_time = time.perf_counter()
    sk, pk = spx_keygen(params=params)
    keygen_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    signature = spx_sign(message, sk, params=params)
    sign_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    result = spx_verify(message, signature, pk, params=params)
    verify_time = time.perf_counter() - start_time

    if not result:
        raise ValueError(f"Проверка подписи не удалась для {instance}!")

    n = params.get("n", "N/A")
    t = 2**params.get("a")

    log_t = "N/A"
    if t is not None and t > 0:
        log_t = int(math.log2(t))

    sec_level = params.get("sec_level", None)
    bitsec = params.get("bitsec", None)
    
    if sec_level is None and n != "N/A":
        if n == 16:
            sec_level = 1
        elif n == 24:
            sec_level = 3
        elif n == 32:
            sec_level = 5
        else:
            sec_level = "N/A"
    
    if bitsec is None and n != "N/A":
        bitsec = n * 8

    return {
        "instance": instance,
        "n": n,
        "h": params.get("h", "N/A"),
        "d": params.get("d", "N/A"),
        "log_t": log_t,
        "k": params.get("k", "N/A"),
        "w": params.get("w", "N/A"),
        "bitsec": bitsec,
        "sec_level": sec_level,
        "sig_bytes": params.get("sig_bytes", "N/A"),
        "keygen_time": keygen_time,
        "sign_time": sign_time,
        "verify_time": verify_time,
        "sig_length": sum(len(x) if isinstance(x, bytes) else sum(len(y) for y in x) for x in signature)
    }

def run_tests():
    """Запускает тесты для всех параметров и выводит таблицу в терминал и Excel."""
    instances = ["128s", "128f", "192s", "192f", "256s", "256f"]
    results = []

    print("Запуск тестов SPHINCS+ с файлом 1 МБ...\n")
    for instance in instances:
        print(f"Тестирование {instance}...")
        result = measure_times(instance)
        results.append(result)

    headers = [
        "Набор параметров", "n", "h", "d", "log(t)", "k", "w", "bitsec", "sec level",
        "Генерация ключей (с)", "Подпись (с)", "Проверка (с)", "Длина подписи (байт)"
    ]
    table_data = [
        [
            r["instance"],
            r["n"],
            r["h"],
            r["d"],
            r["log_t"],
            r["k"],
            r["w"],
            r["bitsec"],
            r["sec_level"],
            f"{r['keygen_time']:.3f}",
            f"{r['sign_time']:.3f}",
            f"{r['verify_time']:.3f}",
            r["sig_length"]
        ]
        for r in results
    ]

    print("\nРезультаты тестов:")
    print(tabulate(table_data, headers=headers, tablefmt="pretty", numalign="center", floatfmt=".3f"))

    wb = Workbook()
    ws = wb.active
    ws.title = "SPHINCS+ Test Results"

    ws.append(headers)
    for r in results:
        ws.append([
            r["instance"],
            r["n"],
            r["h"],
            r["d"],
            r["log_t"],
            r["k"],
            r["w"],
            r["bitsec"],
            r["sec_level"],
            round(r["keygen_time"], 3),
            round(r["sign_time"], 3),
            round(r["verify_time"], 3),
            r["sig_length"]
        ])

    excel_file = "sphincs_test_results.xlsx"
    wb.save(excel_file)
    print(f"\nРезультаты сохранены в файл: {excel_file}")

if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"Ошибка при выполнении тестов: {str(e)}")