import os
import json
from collections import defaultdict
from database import create_database, save_vulnerability

def parse_cve_file(file_path):
    cve_entries = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        items = data if isinstance(data, list) else [data]
        for item in items:
            cve_id = os.path.basename(file_path).replace('.json', '')
            year = int(cve_id.split('-')[1]) if cve_id.startswith('CVE-') else None
            description = item.get('description')
            link = item.get('html_url')
            if all([cve_id, year, description]):
                cve_entries.append({
                    'cveid': cve_id,
                    'year': year,
                    'description': description,
                    'links': [link] if link else []
                })
    except Exception as e:
        print(f"Ошибка при обработке файла {file_path}: {e}")
    return cve_entries

def find_json_files(directory):
    json_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files

if __name__ == "__main__":
    create_database()
    cve_files = find_json_files('PoC-in-GitHub')
    
    if not cve_files:
        print("JSON-файлы не найдены.")
    else:
        print(f"Найдено {len(cve_files)} CVE файлов. Начинается агрегация данных...")
        
        aggregated_data = defaultdict(lambda: {'year': None, 'descriptions': set(), 'links': set()})
        
        for file_path in cve_files:
            cve_data_list = parse_cve_file(file_path)
            for cve_data in cve_data_list:
                cve_id = cve_data['cveid']
                aggregated_data[cve_id]['year'] = aggregated_data[cve_id]['year'] or cve_data['year']
                aggregated_data[cve_id]['descriptions'].add(cve_data['description'])
                if cve_data['links']:
                    aggregated_data[cve_id]['links'].update(cve_data['links'])

        print("Агрегация завершена. Начинается импорт в БД...")
        for cve_id, data in aggregated_data.items():
            # Простое объединение описаний
            description = " | ".join(data['descriptions'])
            save_vulnerability(data['year'], cve_id, description, list(data['links']), source='poc-in-github')
            print(f"Сохранена уязвимость: {cve_id} с {len(data['links'])} ссылками.")
            
        print("Импорт завершен.")