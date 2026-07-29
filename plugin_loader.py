# plugin_loader.py
import importlib
import inspect
from pathlib import Path
from typing import Callable


def discover_plugins() -> dict:
    """
    Автоматически обнаруживает все модули в папке checks/ с async-функциями check_*.
    Возвращает словарь {display_name: async_function}.
    """
    plugins = {}
    
    # Надёжный способ получить путь к папке checks относительно этого файла
    current_dir = Path(__file__).parent
    checks_path = current_dir / "checks"

    if not checks_path.exists():
        print(f"[!] Предупреждение: Папка {checks_path} не найдена!")
        return plugins

    # Итерируемся по всем .py файлам в папке checks
    for file_path in checks_path.glob("*.py"):
        # Пропускаем служебные файлы
        if file_path.name.startswith("_"):
            continue
        
        module_name = file_path.stem
        
        try:
            # Импортируем модуль как checks.имя_файла
            module = importlib.import_module(f"checks.{module_name}")

            # Ищем все async функции с префиксом check_
            for name, obj in inspect.getmembers(module, inspect.isfunction):
                if name.startswith('check_') and inspect.iscoroutinefunction(obj):
                    # Формируем читаемое имя модуля для отчёта (например, "Http Headers")
                    display_name = module_name.replace('_', ' ').title()
                    plugins[display_name] = obj
                    break  # Берём только одну основную функцию check_* из файла

        except Exception as e:
            print(f"[!] Ошибка загрузки плагина {module_name}: {e}")

    return plugins