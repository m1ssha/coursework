import time
from tabulate import tabulate
from openpyxl import Workbook
from src.sphincs import spx_keygen, spx_sign, spx_verify
from src.parameters import get_parameters

def measure_times(instance, message=b"Test message for SPHINCS+"):
    params = get_parameters(instance)
    
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

    return {
        "instance": instance,
        "keygen_time": keygen_time,
        "sign_time": sign_time,
        "verify_time": verify_time,
        "sig_length": sum(len(x) if isinstance(x, bytes) else sum(len(y) for y in x) for x in signature)
    }

def run_tests():
    instances = ["128s", "128f", "192s", "192f", "256s", "256f"]
    results = []

    print("Запуск тестов SPHINCS+...\n")
    for instance in instances:
        print(f"Тестирование {instance}...")
        result = measure_times(instance)
        results.append(result)

    headers = ["Набор параметров", "Генерация ключей (с)", "Подпись (с)", "Проверка (с)", "Длина подписи (байт)"]
    table_data = [
        [
            r["instance"],
            f"{r['keygen_time']:.3f}",
            f"{r['sign_time']:.3f}",
            f"{r['verify_time']:.3f}",
            r["sig_length"]
        ]
        for r in results
    ]

    print("\nРезультаты тестов:")
    print(tabulate(table_data, headers=headers, tablefmt="pretty", floatfmt=".3f"))

    wb = Workbook()
    ws = wb.active
    ws.title = "SPHINCS+ Test Results"

    ws.append(headers)

    for r in results:
        ws.append([
            r["instance"],
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