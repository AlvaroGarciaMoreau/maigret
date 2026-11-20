from flask import (
    Flask,
    render_template,
    request,
    send_from_directory,
    Response,
    flash,
    redirect,
    url_for,
)
from werkzeug.exceptions import NotFound
import logging
import os
import shlex
import shutil
import asyncio
import json
import queue
import uuid
from datetime import datetime
from threading import Thread
from typing import Any, Dict, List, Optional, Tuple
import maigret
import maigret.ai
import maigret.report
import maigret.settings
from maigret.checking import SUPPORTED_IDS, build_cloudflare_bypass_config
from maigret.permutator import Permute
from maigret.result import KeywordMatchStatus, MaigretCheckStatus
from maigret.sites import MaigretDatabase
from maigret.utils import is_country_tag

app = Flask(__name__)
# Use environment variable for secret key, generate random one if not set
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())

# add background job tracking
background_jobs: Dict[str, Any] = {}
job_results: Dict[str, Any] = {}

# Live (streaming) scan jobs, keyed by job_id. Each entry:
#   {'queue': Queue, 'cancelled': bool, 'loop': event loop, 'task': asyncio task}
# ponytail: in-memory, single-process. Entries are dropped when their SSE stream
# ends; a stream that's never consumed lingers — fine for a local tool.
live_jobs: Dict[str, Any] = {}

NUMERIC_ID_TYPES: Tuple[str, ...] = tuple(
    t for t in SUPPORTED_IDS if t != 'username'
)

DEFAULT_FORMATS: Dict[str, Any] = {
    'html': True,
    'pdf': True,
    'xmind': False,
    'csv': True,
    'txt': False,
    'graph': True,
    'neo4j': False,
    'md': False,
    'json': 'ndjson',
}

_FORMAT_FORM_KEYS = (
    'formats_configured',
    'fmt_html',
    'fmt_pdf',
    'fmt_xmind',
    'fmt_csv',
    'fmt_txt',
    'fmt_graph',
    'fmt_neo4j',
    'fmt_md',
    'json_format',
)

_TAG_CACHE: Dict[str, Any] = {}


class StreamNotify:
    """query_notify shim: pushes each per-site check into a queue as an SSE event.

    maigret's search loop calls update() once per finished site check, which is
    exactly the granularity we want to stream to the browser.
    """

    def __init__(self, event_queue, username, id_type='username'):
        self.q = event_queue
        self.username = username
        self.id_type = id_type
        self.total = 0
        self.checked = 0
        self.errors = 0
        self.sites = {}
        # Per-site results collected so far, in the shape build_reports()
        # expects. If the scan gets cancelled mid-way (Stop button), this is
        # what's left to report on — otherwise every already-streamed
        # 'found' event is silently discarded because the search() task
        # never returns to hand back its own results dict.
        self.results = {}

    def set_total(self, total):
        self.total = total
        self.q.put(
            {
                'type': 'start',
                'username': self.username,
                'id_type': self.id_type,
                'total': total,
            }
        )

    def set_sites(self, sites):
        self.sites = sites

    def update(self, result, is_similar=False):
        self.checked += 1
        if not is_similar:
            entry = {'status': result, 'url_user': result.site_url_user}
            site = self.sites.get(result.site_name)
            if site is not None:
                entry['site'] = site
                entry['url_main'] = site.url_main
            self.results[result.site_name] = entry
        if result.status == MaigretCheckStatus.UNKNOWN and not is_similar:
            self.errors += 1
        if result.status == MaigretCheckStatus.CLAIMED and not is_similar:
            ids = {
                k: v
                for k, v in (result.ids_data or {}).items()
                if k != '_extractor' and isinstance(v, (str, int, float))
            }
            keyword_match = bool(
                getattr(result, 'keyword_match_status', None)
                == KeywordMatchStatus.KEYWORD_FOUND
                and getattr(result, 'keywords', None)
            )
            self.q.put(
                {
                    'type': 'found',
                    'username': result.username or self.username,
                    'id_type': self.id_type,
                    'site': result.site_name,
                    'url': result.site_url_user,
                    'ids': ids,
                    'keyword_match': keyword_match,
                }
            )
        self.q.put(
            {
                'type': 'progress',
                'checked': self.checked,
                'total': self.total,
                'errors': self.errors,
                'site': result.site_name,
            }
        )

    # No-op sinks for the rest of the notifier surface the search loop touches.
    def start(self, message=None, id_type="username"):
        if id_type:
            self.id_type = id_type

    def finish(self, message=None):
        pass

    def warning(self, *a, **k):
        pass

    def info(self, *a, **k):
        pass

    def success(self, *a, **k):
        pass

    def enrich(self, *a, **k):
        pass


# Configuration
app.config["MAIGRET_DB_FILE"] = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'resources', 'data.json'
)
app.config["COOKIES_FILE"] = "cookies.txt"
app.config["UPLOAD_FOLDER"] = 'uploads'
app.config["REPORTS_FOLDER"] = os.path.abspath(
    os.getenv('MAIGRET_REPORTS_FOLDER', '/tmp/maigret_reports')
)
app.config["SETTINGS_FILE"] = os.getenv(
    'MAIGRET_SETTINGS_FILE', 'web_settings.json'
)
app.config["DEFAULT_FOLDEROUTPUT"] = "reports"
app.config["ALLOW_CUSTOM_OUTPUT_DIR"] = True

# Search-wide defaults, editable from the Settings modal (base.html). Persisted
# to app.config["SETTINGS_FILE"] so they survive a process restart.
DEFAULT_SETTINGS = {
    'timeout': 10,
    'top_sites': 500,
    'tags': [],
    'excluded_tags': [],
    'site_list': [],
    'proxy': '',
    'tor_proxy': '',
    'i2p_proxy': '',
    'permute': False,
    'disable_recursive_search': False,
    'disable_extracting': False,
    'with_domains': False,
}


def load_settings():
    settings = dict(DEFAULT_SETTINGS)
    path = app.config["SETTINGS_FILE"]
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                settings.update(json.load(f))
        except (json.JSONDecodeError, OSError) as e:
            logging.error(f"Failed to load settings from {path}: {e}")
    return settings


def save_settings(settings):
    settings_path = app.config["SETTINGS_FILE"]
    parent_dir = os.path.dirname(settings_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(settings_path, 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)


def _dedupe_preserve(items: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _parse_tag_values(raw_values: List[str]) -> List[str]:
    tokens: List[str] = []
    for raw in raw_values:
        for part in str(raw).replace(',', ' ').split():
            cleaned = part.strip().lower()
            if cleaned:
                tokens.append(cleaned)
    return _dedupe_preserve(tokens)


def _parse_keyword_values(raw_values: List[str]) -> List[str]:
    tokens: List[str] = []
    for raw in raw_values:
        text = str(raw).strip()
        if not text:
            continue
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = text.split()
        for part in parts:
            cleaned = part.strip()
            if cleaned:
                tokens.append(cleaned)
    return _dedupe_preserve(tokens)


def _parse_site_values(raw_values: List[str]) -> List[str]:
    tokens: List[str] = []
    for raw in raw_values:
        for part in str(raw).split(','):
            cleaned = part.strip()
            if cleaned:
                tokens.append(cleaned)
    return _dedupe_preserve(tokens)


def _get_form_list(form, key: str) -> List[str]:
    if hasattr(form, 'getlist'):
        return form.getlist(key)
    val = form.get(key)
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return list(val)
    return [str(val)]


def parse_settings_form(form):
    try:
        timeout = max(1, int(form.get('timeout')))
    except (TypeError, ValueError):
        timeout = DEFAULT_SETTINGS['timeout']

    try:
        top_sites = max(1, int(form.get('top_sites')))
    except (TypeError, ValueError):
        top_sites = DEFAULT_SETTINGS['top_sites']

    return {
        'timeout': timeout,
        'top_sites': top_sites,
        'tags': _parse_tag_values(_get_form_list(form, 'tags')),
        'excluded_tags': _parse_tag_values(_get_form_list(form, 'excluded_tags')),
        'site_list': _parse_site_values(_get_form_list(form, 'site')),
        'proxy': form.get('proxy', '').strip(),
        'tor_proxy': form.get('tor_proxy', '').strip(),
        'i2p_proxy': form.get('i2p_proxy', '').strip(),
        'permute': 'permute' in form,
        'disable_recursive_search': 'disable_recursive_search' in form,
        'disable_extracting': 'disable_extracting' in form,
        'with_domains': 'with_domains' in form,
    }


@app.context_processor
def inject_settings():
    return {'web_settings': load_settings()}


def setup_logger(log_level, name):
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    return logger


def _parse_formats(form) -> Dict[str, Any]:
    if not any(k in form for k in _FORMAT_FORM_KEYS):
        return dict(DEFAULT_FORMATS)

    json_fmt = str(form.get('json_format', '')).strip().lower()
    if json_fmt not in ('ndjson', 'simple'):
        json_fmt = ''

    return {
        'html': 'fmt_html' in form,
        'pdf': 'fmt_pdf' in form,
        'xmind': 'fmt_xmind' in form,
        'csv': 'fmt_csv' in form,
        'txt': 'fmt_txt' in form,
        'graph': 'fmt_graph' in form,
        'neo4j': 'fmt_neo4j' in form,
        'md': 'fmt_md' in form,
        'json': json_fmt,
    }


def _resolve_id_type(form) -> str:
    id_mode = str(form.get('id_mode', '')).strip().lower()
    raw_id_type = str(form.get('id_type', '')).strip()
    if id_mode == 'username':
        return 'username'
    if raw_id_type == 'auto_ids' or (id_mode == 'numeric' and not raw_id_type):
        return 'auto_ids'
    if raw_id_type in SUPPORTED_IDS:
        return raw_id_type
    return 'username'


def parse_usernames(form):
    usernames_input = form.get('usernames', '').strip()
    return [
        u.strip() for u in usernames_input.replace(',', ' ').split() if u.strip()
    ]


def parse_search_options(form):
    settings = load_settings()
    has_search_form = 'search_form_submitted' in form

    try:
        raw_top = str(form.get('top_sites', '')).strip()
        top_sites = max(1, int(raw_top)) if raw_top else settings['top_sites']
    except (TypeError, ValueError):
        top_sites = settings['top_sites']

    try:
        raw_timeout = str(form.get('timeout', '')).strip()
        timeout = max(1, int(raw_timeout)) if raw_timeout else settings['timeout']
    except (TypeError, ValueError):
        timeout = settings['timeout']

    if has_search_form or 'tags' in form:
        tags = _parse_tag_values(_get_form_list(form, 'tags'))
    else:
        tags = list(settings['tags'])

    if has_search_form or 'excluded_tags' in form:
        excluded_tags = _parse_tag_values(_get_form_list(form, 'excluded_tags'))
    else:
        excluded_tags = list(settings['excluded_tags'])

    if has_search_form or 'site' in form:
        site_list = _parse_site_values(_get_form_list(form, 'site'))
    else:
        site_list = list(settings['site_list'])

    keywords = (
        _parse_keyword_values(_get_form_list(form, 'keywords'))
        if 'keywords' in form
        else []
    )

    all_sites = (
        form.get('mode') == 'full'
        or str(form.get('all_sites', '')).strip().lower() in ('1', 'true', 'on', 'yes')
    )

    folderoutput = str(form.get('folderoutput', '')).strip()
    if not folderoutput:
        folderoutput = app.config.get("DEFAULT_FOLDEROUTPUT", "reports")

    proxy = (
        str(form.get('proxy', '')).strip()
        if has_search_form and 'proxy' in form
        else settings['proxy']
    ) or None
    tor_proxy = (
        str(form.get('tor_proxy', '')).strip()
        if has_search_form and 'tor_proxy' in form
        else settings['tor_proxy']
    ) or None
    i2p_proxy = (
        str(form.get('i2p_proxy', '')).strip()
        if has_search_form and 'i2p_proxy' in form
        else settings['i2p_proxy']
    ) or None

    return {
        'top_sites': top_sites,
        'timeout': timeout,
        'use_cookies': 'use_cookies' in form,
        'all_sites': all_sites,
        'disable_recursive_search': (
            'disable_recursive_search' in form
            if has_search_form
            else settings['disable_recursive_search']
        ),
        'disable_extracting': (
            'disable_extracting' in form
            if has_search_form
            else settings['disable_extracting']
        ),
        'with_domains': (
            'with_domains' in form
            if has_search_form
            else settings['with_domains']
        ),
        'proxy': proxy,
        'tor_proxy': tor_proxy,
        'i2p_proxy': i2p_proxy,
        'permute': 'permute' in form if has_search_form else settings['permute'],
        'tags': tags,
        'excluded_tags': excluded_tags,
        'site_list': site_list,
        'keywords': keywords,
        'id_type': _resolve_id_type(form),
        'folderoutput': folderoutput,
        'formats': _parse_formats(form),
        'ai': 'ai' in form,
        'ai_model': str(form.get('ai_model', '')).strip() or None,
    }


def _shell_quote(value: str) -> str:
    return shlex.quote(str(value))


def build_cli_command(usernames: List[str], options: Dict[str, Any]) -> str:
    """Build the equivalent Maigret CLI command for the given targets and options."""
    targets = [u.strip() for u in usernames if u and u.strip()] or ['user']
    id_type = options.get('id_type') or 'username'

    flags: List[str] = []

    if id_type not in ('username', 'auto_ids') and id_type in SUPPORTED_IDS:
        flags.extend(['--id-type', id_type])

    folderoutput = (options.get('folderoutput') or '').strip()
    if folderoutput and folderoutput != 'reports':
        flags.extend(['-fo', _shell_quote(folderoutput)])

    formats = (
        options['formats']
        if 'formats' in options and options['formats'] is not None
        else DEFAULT_FORMATS
    )
    if formats.get('html'):
        flags.append('--html')
    if formats.get('pdf'):
        flags.append('--pdf')
    if formats.get('xmind'):
        flags.append('--xmind')
    if formats.get('md'):
        flags.append('--md')
    if formats.get('json') in ('ndjson', 'simple'):
        flags.extend(['--json', formats['json']])
    if formats.get('csv'):
        flags.append('--csv')
    if formats.get('txt'):
        flags.append('--txt')
    if formats.get('graph'):
        flags.append('--graph')
    if formats.get('neo4j'):
        flags.append('--neo4j')

    if options.get('all_sites'):
        flags.append('-a')
    else:
        top_sites = options.get('top_sites')
        if top_sites and int(top_sites) != 500:
            flags.extend(['--top-sites', str(int(top_sites))])

    tags = options.get('tags') or []
    if tags:
        flags.extend(['--tags', _shell_quote(','.join(tags))])

    excluded_tags = options.get('excluded_tags') or []
    if excluded_tags:
        flags.extend(['--exclude-tags', _shell_quote(','.join(excluded_tags))])

    site_list = options.get('site_list') or []
    for site_name in site_list:
        flags.extend(['--site', _shell_quote(site_name)])

    keywords = options.get('keywords') or []
    if keywords:
        flags.append('--keywords')
        flags.extend(_shell_quote(kw) for kw in keywords)

    if options.get('permute') and len(targets) > 1 and id_type == 'username':
        flags.append('--permute')
    if options.get('disable_recursive_search'):
        flags.append('--no-recursion')
    if options.get('disable_extracting'):
        flags.append('--no-extracting')
    if options.get('with_domains'):
        flags.append('--with-domains')
    if options.get('use_cookies'):
        flags.extend(['--cookies-jar-file', _shell_quote(app.config["COOKIES_FILE"])])
    if options.get('proxy'):
        flags.extend(['--proxy', _shell_quote(options['proxy'])])
    if options.get('tor_proxy'):
        flags.extend(['--tor-proxy', _shell_quote(options['tor_proxy'])])
    if options.get('i2p_proxy'):
        flags.extend(['--i2p-proxy', _shell_quote(options['i2p_proxy'])])

    if options.get('ai'):
        flags.append('--ai')
        if options.get('ai_model') and options['ai_model'] != 'gpt-5.4':
            flags.extend(['--ai-model', _shell_quote(options['ai_model'])])

    if id_type == 'auto_ids':
        lines = []
        for target in targets:
            for numeric_type in NUMERIC_ID_TYPES:
                lines.append(f"{numeric_type}:{target}")
        printf_arg = _shell_quote('\\n'.join(lines) + '\\n')
        cmd_parts = ['maigret', '--input-file', '-'] + flags
        return f"printf {printf_arg} | {' '.join(cmd_parts)}"

    cmd_parts = ['maigret'] + [_shell_quote(t) for t in targets] + flags
    return ' '.join(cmd_parts)


def expand_search_targets(
    usernames: List[str], options: Dict[str, Any], db: Optional[MaigretDatabase] = None
) -> List[Tuple[str, str]]:
    """Expand usernames into (value, id_type) pairs honoring permute, prefixes, and auto_ids."""
    cleaned = [u.strip() for u in usernames if u and u.strip()]
    base_id_type = options.get('id_type') or 'username'

    if (
        options.get('permute')
        and base_id_type == 'username'
        and len(cleaned) > 1
        and all(':' not in u for u in cleaned)
    ):
        permuted = Permute({u: 'username' for u in cleaned}).gather(method='strict')
        cleaned = list(permuted.keys())

    available_id_types = None
    if db is not None and base_id_type == 'auto_ids':
        available_id_types = {s.type for s in db.sites if not s.disabled}

    expanded: List[Tuple[str, str]] = []
    for entry in cleaned:
        if ':' in entry:
            prefix, _, value = entry.partition(':')
            if prefix in SUPPORTED_IDS and value.strip():
                expanded.append((value.strip(), prefix))
                continue

        if base_id_type == 'auto_ids':
            for numeric_type in NUMERIC_ID_TYPES:
                if available_id_types is None or numeric_type in available_id_types:
                    expanded.append((entry, numeric_type))
        else:
            resolved = base_id_type if base_id_type in SUPPORTED_IDS else 'username'
            expanded.append((entry, resolved))

    return expanded


async def maigret_search(username, options, query_notify=None, id_type=None):
    logger = setup_logger(logging.WARNING, 'maigret')
    try:
        settings = maigret.settings.Settings()
        settings.load()
        cf_bypass_config = build_cloudflare_bypass_config(settings)
        if cf_bypass_config:
            modules_summary = ", ".join(
                f"{m.get('name', m.get('method'))}({m.get('url')})"
                for m in cf_bypass_config["modules"]
            )
            logger.info(
                f"Cloudflare webgate active: triggers={cf_bypass_config['trigger_protection']}, "
                f"modules=[{modules_summary}]"
            )

        db = MaigretDatabase().load_from_path(app.config["MAIGRET_DB_FILE"])

        top_sites = int(options.get('top_sites') or 500)
        if options.get('all_sites'):
            top_sites = 999999999  # effectively all

        tags = options.get('tags', [])
        excluded_tags = options.get('excluded_tags', [])
        site_list = options.get('site_list', [])
        keywords = options.get('keywords', [])
        effective_id_type = id_type or options.get('id_type') or 'username'
        if effective_id_type not in SUPPORTED_IDS:
            effective_id_type = 'username'

        logger.info(
            f"Filtering sites by tags: {tags}, excluded: {excluded_tags}, id_type: {effective_id_type}"
        )

        sites = db.ranked_sites_dict(
            top=top_sites,
            tags=tags,
            excluded_tags=excluded_tags,
            names=site_list,
            disabled=False,
            id_type=effective_id_type,
        )

        logger.info(f"Found {len(sites)} sites matching the criteria")

        if query_notify is not None and hasattr(query_notify, 'set_total'):
            query_notify.set_total(len(sites))
        if query_notify is not None and hasattr(query_notify, 'set_sites'):
            query_notify.set_sites(sites)

        results = await maigret.search(
            username=username,
            site_dict=sites,
            timeout=int(options.get('timeout', 30)),
            logger=logger,
            id_type=effective_id_type,
            query_notify=query_notify,
            no_progressbar=bool(query_notify),
            cookies=app.config["COOKIES_FILE"] if options.get('use_cookies') else None,
            is_parsing_enabled=(not options.get('disable_extracting', False)),
            recursive_search_enabled=(
                not options.get('disable_recursive_search', False)
            ),
            check_domains=options.get('with_domains', False),
            proxy=options.get('proxy', None),
            tor_proxy=options.get('tor_proxy', None),
            i2p_proxy=options.get('i2p_proxy', None),
            cloudflare_bypass=cf_bypass_config,
            keywords=keywords,
        )
        return results
    except Exception as e:
        logger.error(f"Error during search: {str(e)}")
        raise


def _load_db_for_expansion(options: Dict[str, Any]) -> Optional[MaigretDatabase]:
    if options.get('id_type') != 'auto_ids':
        return None
    try:
        return MaigretDatabase().load_from_path(app.config["MAIGRET_DB_FILE"])
    except Exception:
        return None


async def search_multiple_usernames(usernames, options):
    db = _load_db_for_expansion(options)
    targets = expand_search_targets(usernames, options, db=db)
    results = []
    for target, target_id_type in targets:
        try:
            search_results = await maigret_search(
                target, options, id_type=target_id_type
            )
            results.append((target, target_id_type, search_results))
        except Exception as e:
            logging.error(
                f"Error searching {target_id_type} {target}: {str(e)}"
            )
    return results


def sanitize_username_for_path(username: str) -> str:
    """Remove path separators and dangerous components from username for safe file path usage."""
    # Replace path separators and null bytes
    sanitized = username.replace('/', '_').replace('\\', '_').replace('\0', '_')
    # Remove . and .. components
    sanitized = sanitized.strip('.')
    # If empty after sanitization, use a fallback
    return sanitized or '_'


def _resolve_custom_output_dir(folderoutput: str) -> Optional[str]:
    cleaned = (folderoutput or '').strip()
    if not cleaned or cleaned == 'reports' or '\0' in cleaned:
        return None
    if not app.config.get("ALLOW_CUSTOM_OUTPUT_DIR", True):
        return None
    if os.path.isabs(cleaned):
        return os.path.normpath(cleaned)
    base_dir = app.config.get("OUTPUT_BASE_DIR", os.getcwd())
    return os.path.normpath(os.path.join(base_dir, cleaned))


def _copy_generated_files(session_folder: str, export_dir: str, rel_files: List[str]):
    os.makedirs(export_dir, exist_ok=True)
    for rel_path in rel_files:
        if not rel_path:
            continue
        src = os.path.join(app.config["REPORTS_FOLDER"], rel_path)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(export_dir, os.path.basename(src)))


def _is_ai_configured() -> bool:
    settings = maigret.settings.Settings()
    settings.load()
    return bool(maigret.ai.resolve_api_key(settings))


async def _maybe_run_ai_analysis(
    general_results: list,
    options: Dict[str, Any],
    session_folder: str,
    exported_folder: Optional[str] = None,
) -> Dict[str, Any]:
    if not options.get('ai') or not general_results:
        return {}

    settings = maigret.settings.Settings()
    settings.load()
    api_key = maigret.ai.resolve_api_key(settings)
    if not api_key:
        return {
            'ai_error': (
                'Falta OPENAI_API_KEY en el entorno o openai_api_key en settings.json '
                'para ejecutar el resumen con IA (--ai).'
            )
        }

    context = maigret.report.generate_report_context(general_results)
    run_flags = []
    if options.get('tags'):
        run_flags.append(f"--tags {','.join(options['tags'])}")
    if options.get('site_list'):
        run_flags.append(f"--site {','.join(options['site_list'])}")
    if options.get('all_sites'):
        run_flags.append("--all-sites")
    run_info = {
        'sites_count': sum(len(d) for _, _, d in general_results),
        'flags': ' '.join(run_flags) if run_flags else None,
    }
    md_report = maigret.report.generate_markdown_report(context, run_info=run_info)
    model = options.get('ai_model') or getattr(settings, 'openai_model', 'gpt-5.4')
    api_base_url = getattr(
        settings, 'openai_api_base_url', 'https://api.openai.com/v1'
    )

    try:
        analysis = await maigret.ai.get_ai_analysis(
            api_key=api_key,
            markdown_report=md_report,
            model=model,
            api_base_url=api_base_url,
            silent=True,
        )
    except Exception as e:
        return {'ai_error': f'Error en análisis IA: {e}'}

    ai_info: Dict[str, Any] = {'ai_analysis': analysis}
    if session_folder:
        ai_filename = 'ai_summary.md'
        ai_path = os.path.join(session_folder, ai_filename)
        with open(ai_path, 'w', encoding='utf-8') as f:
            f.write(analysis)

        if exported_folder:
            try:
                os.makedirs(exported_folder, exist_ok=True)
                shutil.copy2(ai_path, os.path.join(exported_folder, ai_filename))
            except OSError as e:
                logging.warning(f"Could not copy AI summary to {exported_folder}: {e}")

        ai_info['ai_file'] = os.path.join(os.path.basename(session_folder), ai_filename)
    return ai_info


def build_reports(general_results, usernames, session_key, options=None):
    """Write selected per-username and combined reports to disk.

    Shared by the background /search job and the live SSE /api/scan job, so
    both flows land on the same results.html (report buttons + profile list).
    """
    opts = options or {}
    formats = (
        opts['formats']
        if 'formats' in opts and opts['formats'] is not None
        else DEFAULT_FORMATS
    )

    os.makedirs(app.config["REPORTS_FOLDER"], exist_ok=True)
    session_dir_name = f"search_{session_key}"
    session_folder = os.path.join(app.config["REPORTS_FOLDER"], session_dir_name)
    os.makedirs(session_folder, exist_ok=True)

    db = MaigretDatabase().load_from_path(app.config["MAIGRET_DB_FILE"])
    warnings: List[str] = []
    generated_rel_files: List[str] = []

    graph_file = None
    if formats.get('graph'):
        graph_rel = os.path.join(session_dir_name, "combined_graph.html")
        graph_path = os.path.join(session_folder, "combined_graph.html")
        maigret.report.save_graph_report(graph_path, general_results, db)
        graph_file = graph_rel
        generated_rel_files.append(graph_rel)

    neo4j_file = None
    if formats.get('neo4j'):
        neo4j_rel = os.path.join(session_dir_name, "combined_neo4j.cypher")
        neo4j_path = os.path.join(session_folder, "combined_neo4j.cypher")
        maigret.report.save_neo4j_report(neo4j_path, general_results, db)
        neo4j_file = neo4j_rel
        generated_rel_files.append(neo4j_rel)

    needs_context = any(
        formats.get(k) for k in ('html', 'pdf', 'md')
    )
    context = (
        maigret.report.generate_report_context(general_results)
        if needs_context and general_results
        else None
    )

    run_info = None
    if formats.get('md'):
        run_flags = []
        if opts.get('tags'):
            run_flags.append(f"--tags {','.join(opts['tags'])}")
        if opts.get('site_list'):
            run_flags.append(f"--site {','.join(opts['site_list'])}")
        if opts.get('all_sites'):
            run_flags.append("--all-sites")
        run_info = {
            'sites_count': sum(len(d) for _, _, d in general_results),
            'flags': ' '.join(run_flags) if run_flags else None,
        }

    # Distinguish filenames when the same target appears with multiple id_types (e.g., auto_ids)
    name_counts: Dict[str, int] = {}
    for username, _, _ in general_results:
        safe_u = sanitize_username_for_path(username)
        name_counts[safe_u] = name_counts.get(safe_u, 0) + 1

    individual_reports = []
    found_count = 0
    json_fmt = formats.get('json') or ''

    for username, id_type, results in general_results:
        safe_username = sanitize_username_for_path(username)
        needs_id_suffix = name_counts.get(safe_username, 0) > 1 or id_type != 'username'
        base_name = (
            f"report_{safe_username}_{id_type}"
            if needs_id_suffix
            else f"report_{safe_username}"
        )
        report_base = os.path.join(session_folder, base_name)

        entry_files: Dict[str, Optional[str]] = {
            'csv_file': None,
            'json_file': None,
            'pdf_file': None,
            'html_file': None,
            'txt_file': None,
            'xmind_file': None,
            'md_file': None,
        }

        if formats.get('csv'):
            csv_path = f"{report_base}.csv"
            maigret.report.save_csv_report(csv_path, username, results)
            rel = os.path.join(session_dir_name, f"{base_name}.csv")
            entry_files['csv_file'] = rel
            generated_rel_files.append(rel)

        if formats.get('txt'):
            txt_path = f"{report_base}.txt"
            maigret.report.save_txt_report(txt_path, username, results)
            rel = os.path.join(session_dir_name, f"{base_name}.txt")
            entry_files['txt_file'] = rel
            generated_rel_files.append(rel)

        if formats.get('xmind'):
            xmind_path = f"{report_base}.xmind"
            maigret.report.save_xmind_report(xmind_path, username, results)
            rel = os.path.join(session_dir_name, f"{base_name}.xmind")
            entry_files['xmind_file'] = rel
            generated_rel_files.append(rel)

        if json_fmt in ('ndjson', 'simple'):
            json_filename = f"{base_name}_{json_fmt}.json"
            json_path = os.path.join(session_folder, json_filename)
            maigret.report.save_json_report(
                json_path, username, results, report_type=json_fmt
            )
            rel = os.path.join(session_dir_name, json_filename)
            entry_files['json_file'] = rel
            generated_rel_files.append(rel)

        if formats.get('pdf') and context is not None:
            pdf_path = f"{report_base}.pdf"
            try:
                maigret.report.save_pdf_report(pdf_path, context)
                rel = os.path.join(session_dir_name, f"{base_name}.pdf")
                entry_files['pdf_file'] = rel
                generated_rel_files.append(rel)
            except RuntimeError as e:
                warnings.append(str(e))

        if formats.get('html') and context is not None:
            html_path = f"{report_base}.html"
            maigret.report.save_html_report(html_path, context)
            rel = os.path.join(session_dir_name, f"{base_name}.html")
            entry_files['html_file'] = rel
            generated_rel_files.append(rel)

        if formats.get('md') and context is not None:
            md_path = f"{report_base}.md"
            maigret.report.save_markdown_report(md_path, context, run_info=run_info)
            rel = os.path.join(session_dir_name, f"{base_name}.md")
            entry_files['md_file'] = rel
            generated_rel_files.append(rel)

        claimed_profiles = []
        for site_name, site_data in results.items():
            status_obj = site_data.get('status')
            if status_obj and status_obj.status == MaigretCheckStatus.CLAIMED:
                keyword_match = bool(
                    getattr(status_obj, 'keyword_match_status', None)
                    == KeywordMatchStatus.KEYWORD_FOUND
                    and getattr(status_obj, 'keywords', None)
                )
                claimed_profiles.append(
                    {
                        'site_name': site_name,
                        'url': site_data.get('url_user', ''),
                        'tags': status_obj.tags if status_obj else [],
                        'keyword_match': keyword_match,
                    }
                )

        found_count += len(claimed_profiles)
        individual_reports.append(
            {
                'username': username,
                'id_type': id_type,
                **entry_files,
                'claimed_profiles': claimed_profiles,
            }
        )

    exported_folder = None
    export_error = None
    target_export_dir = _resolve_custom_output_dir(opts.get('folderoutput', ''))
    if target_export_dir:
        try:
            _copy_generated_files(session_folder, target_export_dir, generated_rel_files)
            exported_folder = target_export_dir
        except OSError as e:
            export_error = f"No se pudo escribir en '{target_export_dir}': {e}"
            logging.error(export_error)

    return {
        'status': 'completed',
        'session_folder': session_dir_name,
        'session_folder_path': session_folder,
        'exported_folder': exported_folder,
        'export_error': export_error,
        'graph_file': graph_file,
        'neo4j_file': neo4j_file,
        'usernames': usernames,
        'individual_reports': individual_reports,
        'found_count': found_count,
        'cli_command': build_cli_command(usernames, opts) if opts else None,
        'formats': formats,
        'json_format': json_fmt,
        'keywords': opts.get('keywords', []),
        'id_type': opts.get('id_type', 'username'),
        'warnings': _dedupe_preserve(warnings),
    }


def process_search_task(usernames, options, timestamp):
    started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        general_results = loop.run_until_complete(
            search_multiple_usernames(usernames, options)
        )
        report_data = build_reports(
            general_results, usernames, timestamp, options=options
        )
        ai_info = loop.run_until_complete(
            _maybe_run_ai_analysis(
                general_results,
                options,
                report_data.get('session_folder_path'),
                report_data.get('exported_folder'),
            )
        )
        report_data.update(ai_info)
        job_results[timestamp] = report_data

    except Exception as e:
        logging.error(f"Error in search task for timestamp {timestamp}: {str(e)}")
        job_results[timestamp] = {
            'status': 'failed',
            'error': str(e),
            'usernames': usernames,
        }
    finally:
        loop.close()
        job_results[timestamp]['started_at'] = started_at
        background_jobs[timestamp]['completed'] = True


async def _stream_search(job, usernames, options):
    q = job['queue']
    db = _load_db_for_expansion(options)
    targets = expand_search_targets(usernames, options, db=db)
    general_results = []
    for target, target_id_type in targets:
        if job['cancelled']:
            break
        notify = StreamNotify(q, target, id_type=target_id_type)
        task = asyncio.ensure_future(
            maigret_search(
                target, options, query_notify=notify, id_type=target_id_type
            )
        )
        job['task'] = task
        try:
            results = await task
            general_results.append((target, target_id_type, results))
        except asyncio.CancelledError:
            # The task never got to return its own results dict, but every
            # site checked before cancellation already streamed a 'found' /
            # 'progress' event and was captured by the notifier — report on
            # that instead of throwing it away.
            if notify.results:
                general_results.append((target, target_id_type, notify.results))
            q.put({'type': 'stopped', 'username': target})
            break
        except Exception as e:
            if notify.results:
                general_results.append((target, target_id_type, notify.results))
            q.put({'type': 'error', 'message': str(e), 'username': target})
    return general_results


def run_stream_job(job_id, usernames, options):
    started_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    job = live_jobs[job_id]
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    job['loop'] = loop
    general_results = []
    ai_info: Dict[str, Any] = {}
    report_data = None
    try:
        general_results = loop.run_until_complete(
            _stream_search(job, usernames, options)
        )
        if general_results:
            report_data = build_reports(
                general_results, usernames, job_id, options=options
            )
            ai_info = loop.run_until_complete(
                _maybe_run_ai_analysis(
                    general_results,
                    options,
                    report_data.get('session_folder_path'),
                    report_data.get('exported_folder'),
                )
            )
    except Exception as e:
        logging.error(f"Error in live scan {job_id}: {str(e)}")
        job['queue'].put({'type': 'error', 'message': str(e)})
    finally:
        loop.close()

    # Same report files + results page as the classic /search flow, so the
    # live graph is a progress view, not a replacement for the report.
    done_event: Dict[str, Any] = {'type': 'done'}
    if report_data is not None:
        report_data.update(ai_info)
        report_data['started_at'] = started_at
        job_results[job_id] = report_data
        done_event['redirect'] = f"/results/search_{job_id}"
        done_event['found_count'] = report_data.get('found_count', 0)
    elif general_results:
        try:
            fallback_report = build_reports(
                general_results, usernames, job_id, options=options
            )
            fallback_report['started_at'] = started_at
            job_results[job_id] = fallback_report
            done_event['redirect'] = f"/results/search_{job_id}"
            done_event['found_count'] = fallback_report.get('found_count', 0)
        except Exception as e:
            logging.error(f"Error building reports for live scan {job_id}: {str(e)}")
    job['queue'].put(done_event)


def start_live_job(usernames, options):
    job_id = uuid.uuid4().hex
    live_jobs[job_id] = {
        'queue': queue.Queue(),
        'cancelled': False,
        'loop': None,
        'task': None,
    }
    Thread(target=run_stream_job, args=(job_id, usernames, options)).start()
    return job_id


@app.route('/api/scan', methods=['POST'])
def scan_start():
    usernames = parse_usernames(request.form)
    if not usernames:
        return {'error': 'At least one username is required'}, 400

    options = parse_search_options(request.form)
    job_id = start_live_job(usernames, options)
    return {'job_id': job_id}


@app.route('/api/scan/<job_id>/stream')
def scan_stream(job_id):
    job = live_jobs.get(job_id)
    if not job:
        finished = job_results.get(job_id)
        if finished and finished.get('status') == 'completed':
            def finished_gen():
                payload = {
                    'type': 'done',
                    'redirect': f"/results/{finished['session_folder']}",
                    'found_count': finished.get('found_count', 0),
                }
                yield f"data: {json.dumps(payload)}\n\n"

            return Response(finished_gen(), mimetype='text/event-stream')
        return "Unknown job", 404

    def gen():
        try:
            while True:
                event = job['queue'].get()
                yield f"data: {json.dumps(event)}\n\n"
                if event.get('type') == 'done':
                    break
        finally:
            live_jobs.pop(job_id, None)

    return Response(gen(), mimetype='text/event-stream')


@app.route('/api/scan/<job_id>/stop', methods=['POST'])
def scan_stop(job_id):
    job = live_jobs.get(job_id)
    if not job:
        return {'error': 'unknown job'}, 404

    job['cancelled'] = True
    loop = job.get('loop')
    task = job.get('task')
    if loop and task:
        loop.call_soon_threadsafe(task.cancel)
    return {'ok': True}


@app.route('/')
def index():
    return render_template(
        'index.html',
        numeric_id_types=NUMERIC_ID_TYPES,
        default_folderoutput=app.config.get("DEFAULT_FOLDEROUTPUT", "reports"),
        ai_configured=_is_ai_configured(),
    )


@app.route('/api/sites')
def api_sites():
    """Site names/URLs for the Filters site-picker datalist, fetched lazily
    from the Settings modal instead of loading the DB on every page render."""
    db = MaigretDatabase().load_from_path(app.config["MAIGRET_DB_FILE"])
    site_options = []
    for site in db.sites:
        site_options.append(site.name)
        if site.url_main and site.url_main not in site_options:
            site_options.append(site.url_main)
    return {'sites': sorted(set(site_options))}


@app.route('/api/tags')
def api_tags():
    """Return available category and country tags from the configured database."""
    db_path = app.config["MAIGRET_DB_FILE"]
    try:
        mtime = os.path.getmtime(db_path)
    except OSError:
        mtime = None

    cached = _TAG_CACHE.get(db_path)
    if cached and cached.get('mtime') == mtime:
        return cached['data']

    db = MaigretDatabase().load_from_path(db_path)
    all_tags = set(getattr(db, '_tags', []) or [])
    for site in db.sites:
        for tag in site.tags:
            if tag:
                all_tags.add(tag)

    category_tags = sorted(t for t in all_tags if not is_country_tag(t))
    country_tags = sorted(t for t in all_tags if is_country_tag(t))
    payload = {'category_tags': category_tags, 'country_tags': country_tags}
    _TAG_CACHE[db_path] = {'mtime': mtime, 'data': payload}
    return payload


@app.route('/settings', methods=['POST'])
def settings_update():
    save_settings(parse_settings_form(request.form))
    flash('Settings saved.', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route('/history')
def history():
    entries = sorted(
        job_results.values(), key=lambda r: r.get('started_at', ''), reverse=True
    )
    return render_template('history.html', entries=entries)


@app.route('/live', methods=['POST'])
def live_start():
    usernames = parse_usernames(request.form)
    if not usernames:
        flash('At least one username is required', 'danger')
        return redirect(url_for('index'))

    options = parse_search_options(request.form)
    job_id = start_live_job(usernames, options)
    return redirect(url_for('live_results', job_id=job_id))


@app.route('/live/<job_id>')
def live_results(job_id):
    result = job_results.get(job_id)
    if job_id not in live_jobs and not result:
        flash('Unknown or expired scan session.', 'danger')
        return redirect(url_for('index'))

    done_redirect = None
    done_found_count = 0
    if result and result.get('status') == 'completed':
        done_redirect = url_for('results', session_id=result['session_folder'])
        done_found_count = result.get('found_count', 0)

    return render_template(
        'live.html',
        job_id=job_id,
        done_redirect=done_redirect,
        done_found_count=done_found_count,
    )


# Modified search route
@app.route('/search', methods=['POST'])
def search():
    usernames = parse_usernames(request.form)
    if not usernames:
        flash('At least one username is required', 'danger')
        return redirect(url_for('index'))

    # Create timestamp for this search session
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    options = parse_search_options(request.form)
    logging.info(
        f"Starting search for usernames: {usernames} with tags: {options['tags']}, "
        f"excluded: {options['excluded_tags']}, id_type: {options['id_type']}"
    )

    # Start background job
    background_jobs[timestamp] = {
        'completed': False,
        'thread': Thread(
            target=process_search_task, args=(usernames, options, timestamp)
        ),
    }
    background_jobs[timestamp]['thread'].start()  # type: ignore[union-attr]

    return redirect(url_for('status', timestamp=timestamp))


@app.route('/status/<timestamp>')
def status(timestamp):
    logging.info(f"Status check for timestamp: {timestamp}")

    # Validate timestamp
    if timestamp not in background_jobs:
        flash('Invalid search session.', 'danger')
        logging.error(f"Invalid search session: {timestamp}")
        return redirect(url_for('index'))

    # Check if job is completed
    if background_jobs[timestamp]['completed']:
        result = job_results.get(timestamp)
        if not result:
            flash('No results found for this search session.', 'warning')
            logging.error(f"No results found for completed session: {timestamp}")
            return redirect(url_for('index'))

        if result['status'] == 'completed':
            # Note: use the session_folder from the results to redirect
            return redirect(url_for('results', session_id=result['session_folder']))
        else:
            error_msg = result.get('error', 'Unknown error occurred.')
            flash(f'Search failed: {error_msg}', 'danger')
            logging.error(f"Search failed for session {timestamp}: {error_msg}")
            return redirect(url_for('index'))

    # If job is still running, show a status page
    return render_template('status.html', timestamp=timestamp)


@app.route('/results/<session_id>')
def results(session_id):
    # Find completed results that match this session_folder
    result_data = next(
        (
            r
            for r in job_results.values()
            if r.get('status') == 'completed' and r['session_folder'] == session_id
        ),
        None,
    )

    if not result_data:
        flash('No results found for this session ID.', 'danger')
        logging.error(f"Results for session {session_id} not found in job_results.")
        return redirect(url_for('index'))

    return render_template(
        'results.html',
        usernames=result_data['usernames'],
        graph_file=result_data.get('graph_file'),
        neo4j_file=result_data.get('neo4j_file'),
        individual_reports=result_data['individual_reports'],
        timestamp=session_id.replace('search_', ''),
        cli_command=result_data.get('cli_command'),
        session_folder_path=result_data.get('session_folder_path'),
        exported_folder=result_data.get('exported_folder'),
        export_error=result_data.get('export_error'),
        ai_analysis=result_data.get('ai_analysis'),
        ai_file=result_data.get('ai_file'),
        ai_error=result_data.get('ai_error'),
        warnings=result_data.get('warnings', []),
        keywords=result_data.get('keywords', []),
        json_format=result_data.get('json_format', ''),
        id_type=result_data.get('id_type', 'username'),
        found_count=result_data.get('found_count', 0),
    )


@app.route('/reports/<path:filename>')
def download_report(filename):
    reports_root = app.config["REPORTS_FOLDER"]
    os.makedirs(reports_root, exist_ok=True)
    try:
        return send_from_directory(reports_root, filename)
    except NotFound:
        return "File not found", 404
    except Exception as e:
        logging.error(f"Error serving file {filename}: {str(e)}")
        return "File not found", 404


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']

    # Host configuration: secure by default
    # Use 127.0.0.1 for local development, 0.0.0.0 only if explicitly set
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', '5000'))

    app.run(host=host, port=port, debug=debug_mode)
