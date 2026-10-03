import requests
from bs4 import BeautifulSoup
import re
import os
from urllib.parse import urljoin, urlparse
from database import create_database, save_vulnerability
import time
import argparse

BASE_URL = "https://t.me/s/poc_in_zip"
ZIP_DIR = "poc_zips"
STATE_FILE = '.last_telegram_post_id'


def parse_telegram_post(post_id):
    """Парсит один пост, извлекает CVE, desc, links, скачивает ZIP."""
    url = f"{BASE_URL}/{post_id}"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"Ошибка запроса {url}: {e}")
        return None

    soup = BeautifulSoup(response.text, 'lxml')
    message_text_elem = soup.find('div', class_='tgme_widget_message_text')

    if not message_text_elem:
        print(f"Текст поста не найден в {url}")
        return None

    description = message_text_elem.get_text(strip=True)

    # Ссылки только на репозитории и архивы
    repo_domains = ['github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net']
    post_links = []
    for a in message_text_elem.find_all('a', href=True):
        href = a['href']
        link_lower = href.lower()
        if any(domain in link_lower for domain in repo_domains) or '.zip' in link_lower:
            if 't.me' not in link_lower:
                post_links.append(href)

    # CVE ID: улучшенный regex
    cve_match = re.search(r'(?i)CVE[-: ]*(\d{4})[-: ]*(\d+)', description)
    if not cve_match:
        print(f"CVE не найдено в {url}")
        return None

    year = int(cve_match.group(1))
    cve_num = cve_match.group(2)
    cve_id = f"CVE-{year}-{cve_num}".upper()

    links = list(set(post_links))

    # Сохранить в БД
    if links:
        save_vulnerability(year, cve_id, description, links, source='telegram')
        print(f"  [+] {cve_id} | {len(links)} ссылок")
    else:
        print(f"  [-] {cve_id} — ссылок нет, пропущен")

    # Скачать ZIP
    os.makedirs(ZIP_DIR, exist_ok=True)
    for link in links:
        parsed = urlparse(link)
        if '.zip' in parsed.path.lower():
            zip_filename = f"{cve_id}.zip"
            zip_path = os.path.join(ZIP_DIR, zip_filename)
            if os.path.exists(zip_path):
                break
            try:
                zip_resp = requests.get(link, headers=headers, stream=True, timeout=30)
                zip_resp.raise_for_status()
                with open(zip_path, 'wb') as f:
                    for chunk in zip_resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                print(f"  ZIP скачан: {zip_path}")
                break
            except Exception as e:
                print(f"  Ошибка скачивания ZIP {link}: {e}")

    return cve_id


def get_recent_post_ids(limit=200, min_id=0):
    """Получает post_id через постраничную навигацию.
    limit=0 означает без ограничения по количеству постов.
    """
    post_ids = set()
    before = None
    page_count = 0

    while True:
        if limit > 0 and len(post_ids) >= limit:
            break

        if before:
            url = f"{BASE_URL}?before={before}"
        else:
            url = BASE_URL

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
        except Exception as e:
            print(f"Ошибка загрузки {url}: {e}")
            break

        soup = BeautifulSoup(response.text, 'lxml')
        page_ids = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if 'poc_in_zip' in href:
                match = re.search(r'/(\d+)$', href)
                if match:
                    pid = int(match.group(1))
                    if pid >= min_id:
                        page_ids.append(pid)

        if not page_ids:
            break

        next_before = min(page_ids)
        if before is not None and next_before >= before:
            print("Пагинация остановлена: курсор не изменился")
            break

        post_ids.update(page_ids)
        before = next_before
        page_count += 1
        print(f"  Страница {page_count}: +{len(page_ids)} IDs, всего {len(post_ids)}")
        time.sleep(1)

    result = sorted(post_ids, reverse=True)
    if limit > 0:
        result = result[:limit]
    print(f"Найдено {len(result)} постов (от {result[0] if result else '—'} до {result[-1] if result else '—'})")
    return result


def load_last_id():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return int(f.read().strip())
    return 0


def save_last_id(post_id):
    with open(STATE_FILE, 'w') as f:
        f.write(str(post_id))


def cron_mode(full=False):
    """Авто-режим: парсит новые посты."""
    create_database()
    os.makedirs(ZIP_DIR, exist_ok=True)

    last_id = load_last_id()

    if full:
        new_ids = get_recent_post_ids(0, 0)  # limit=0 = без лимита
        print(f"Полный парсинг: {len(new_ids)} постов")
    else:
        recent_ids = get_recent_post_ids(500, last_id)
        new_ids = [pid for pid in recent_ids if pid > last_id]
        if not new_ids:
            print("Новых постов не найдено.")
            return
        print(f"Новых постов: {len(new_ids)} (последний известный {last_id})")

    parsed_count = 0
    for post_id in new_ids:
        result = parse_telegram_post(post_id)
        if result:
            parsed_count += 1
        time.sleep(2)

    # Сохраняем самый новый ID
    if new_ids and not full:
        save_last_id(max(new_ids))

    print(f"Обработано: {parsed_count}/{len(new_ids)} постов с CVE")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Telegram PoC Parser')
    parser.add_argument('--post_id', type=int, help='Single post ID')
    parser.add_argument('--start_id', type=int, default=11100, help='Batch start')
    parser.add_argument('--end_id', type=int, default=11200, help='Batch end')
    parser.add_argument('--batch', action='store_true', help='Batch mode')
    parser.add_argument('--full', action='store_true', help='Parse all recent posts (ignore last_id)')
    args = parser.parse_args()

    create_database()
    os.makedirs(ZIP_DIR, exist_ok=True)

    if args.post_id:
        parse_telegram_post(args.post_id)
    elif args.batch:
        for post_id in range(args.start_id, args.end_id + 1):
            parse_telegram_post(post_id)
            time.sleep(1)
    else:
        cron_mode(full=args.full)
