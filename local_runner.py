"""
local_runner.py
Простой локальный запуск build_sub.py для VPN Builder V2.6

Запуск:
    python local_runner.py
"""

import os
import sys
import time
import subprocess


def main():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    build_script = os.path.join(project_dir, "build_sub.py")

    if not os.path.exists(build_script):
        print("❌ build_sub.py не найден")
        print(f"Путь: {build_script}")
        sys.exit(1)

    print("=" * 64)
    print("VPN Builder V2.6 — Local Runner")
    print("=" * 64)
    print(f"Папка проекта: {project_dir}")
    print(f"Скрипт сборки: {build_script}")
    print()

    start = time.monotonic()

    try:
        result = subprocess.run(
            [sys.executable, build_script],
            cwd=project_dir,
            check=False,
        )
    except KeyboardInterrupt:
        print("\n⛔ Остановлено пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Ошибка запуска build_sub.py: {e}")
        sys.exit(1)

    elapsed = time.monotonic() - start

    print()
    print("=" * 64)
    if result.returncode == 0:
        print("✅ Local Runner завершён успешно")
    else:
        print(f"⚠️ build_sub.py завершился с кодом: {result.returncode}")
    print("=" * 64)
    print(f"Время выполнения: {elapsed:.1f}с")
    print(f"Результаты смотри в папке: {os.path.join(project_dir, 'outputs')}")


if __name__ == "__main__":
    main()