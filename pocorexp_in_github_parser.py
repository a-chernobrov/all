import os
import re
from database import create_database, save_vulnerability, count_vulnerabilities

BASE_DIR = 'PocOrExp_in_Github'


def parse_readme(filepath):
    """
    Парсит README.md формата:
    ## CVE-YYYY-NNNNN
    Description...

    - [https://github.com/...](https://github.com/...) : ![starts](...) ![forks](...)
    """
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    entries = []
    # Разбиваем по заголовкам CVE: ## CVE-YYYY-NNNNN
    blocks = re.split(r'^## (CVE-\d{4}-\d+)', content, flags=re.MULTILINE)

    for i in range(1, len(blocks), 2):
        cve_id = blocks[i].strip()
        block = blocks[i + 1] if i + 1 < len(blocks) else ''

        lines = block.strip().split('\n')

        # Описание — первая непустая строка (не ссылка, не бейдж)
        description = ''
        for line in lines:
            line = line.strip()
            if line and not line.startswith('- [') and not line.startswith('!['):
                description = line
                break

        # Ссылки — строки вида `- [URL](URL)`
        links = []
        for line in lines:
            match = re.match(r'- \[(https?://[^\]]+)\]\(https?://[^\)]+\)', line.strip())
            if match:
                links.append(match.group(1))

        year_match = re.match(r'CVE-(\d{4})-\d+', cve_id)
        year = int(year_match.group(1)) if year_match else None

        if year and description:
            entries.append({
                'cve_id': cve_id,
                'year': year,
                'description': description,
                'links': links,
            })

    return entries


def run():
    create_database()

    if not os.path.isdir(BASE_DIR):
        print(f"Директория {BASE_DIR} не найдена")
        return

    sources = [
        ('PocOrExp.md', 'pocorexp-in-github'),
        ('Today.md', 'pocorexp-in-github-today'),
    ]

    total_parsed = 0
    for filename, source in sources:
        filepath = os.path.join(BASE_DIR, filename)
        if not os.path.exists(filepath):
            continue
        print(f"Парсинг {filepath}...")
        entries = parse_readme(filepath)
        print(f"  Найдено {len(entries)} CVE")
        for e in entries:
            save_vulnerability(e['year'], e['cve_id'], e['description'], e['links'], source=source)
        total_parsed += len(entries)
        print(f"  Сохранено: {len(entries)}")

    total = count_vulnerabilities()
    print(f"\nГотово. Обработано записей: {total_parsed}. Всего в БД: {total}")


if __name__ == '__main__':
    run()
