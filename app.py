import copy
import hmac
import http.cookiejar
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http import HTTPStatus
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
for path in (BASE_DIR, ROOT_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)



WEB = "https://zafiro.sinai.net.co"
API = "https://zafiroapi.sinai.net.co"
LOGIN = WEB + "/Web/Default.aspx"
BOOT = WEB + "/Web/BootstrapSesion.aspx"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _field(html, name):
    m = re.search('name="%s"[^>]*value="([^"]*)"' % re.escape(name), html)
    return m.group(1) if m else ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class SinaiClient:
    def __init__(self, user, password, label="cuenta"):
        self.user = user
        self.password = password
        self.label = label
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.op.addheaders = [("User-Agent", UA), ("Accept-Language", "es-CO,es;q=0.9")]
        self.nore = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj), NoRedirect)
        self.nore.addheaders = [("User-Agent", UA), ("Accept-Language", "es-CO,es;q=0.9")]
        self.logged_in = False
        self.landing_url = None
        self.landing_body = ""

    def _req(self, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        return req

    def _get_noredir(self, url):
        try:
            r = self.nore.open(self._req(url), timeout=30)
            return r.status, r.headers.get("Location"), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode("utf-8", "replace")

    def _get_follow(self, url):
        r = self.op.open(self._req(url), timeout=30)
        return r.status, r.geturl(), r.read().decode("utf-8", "replace")

    def login(self):
        html = self.op.open(LOGIN, timeout=30).read().decode("utf-8", "replace")

        data = {
            "__EVENTTARGET": "ctl00$Entrar",
            "__EVENTARGUMENT": "",
            "__LASTFOCUS": "",
            "__VIEWSTATE": _field(html, "__VIEWSTATE"),
            "__VIEWSTATEGENERATOR": _field(html, "__VIEWSTATEGENERATOR"),
            "__EVENTVALIDATION": _field(html, "__EVENTVALIDATION"),
            "ctl00$UsernameTxt": self.user,
            "ctl00$PasswordTxt": self.password,
        }
        resp = self.op.open(LOGIN, urllib.parse.urlencode(data).encode(), timeout=30)
        self.login_body = resp.read().decode("utf-8", "replace")
        self.logged_in = "PasswordTxt" not in self.login_body and "js-login" not in self.login_body
        self.login_final = resp.geturl()
        return self.logged_in

    def connect(self):
        """Login + ciclo de bootstrap hasta entrar al panel del rol."""
        if not self.logged_in:
            self.login()
        page = self.login_body
        url = WEB + "/Web/UserRouter.aspx"
        for _attempt in range(4):
            ticket = _field(page, "ticket")
            if not ticket:
                _, page = self._get_follow(BOOT)[1:]
                ticket = _field(page, "ticket")
            if not ticket:
                raise RuntimeError("Sin ticket de bootstrap")
            renovar = _field(page, "renovarUrl")
            body = urllib.parse.urlencode({"ticket": ticket, "renovarUrl": renovar}).encode()
            try:
                self.nore.open(
                    self._req(
                        API + "/auth/bootstrap",
                        data=body,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    ),
                    timeout=30,
                )
                loc = None
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location")
            if not loc:
                continue
            url = loc
            for _step in range(6):
                st, loc2, html = self._get_noredir(url)
                if st in (301, 302, 303, 307, 308) and loc2:
                    loc2 = urllib.parse.urljoin(url, loc2)
                    if "BootstrapSesion" in loc2:
                        _, page = self._get_follow(loc2)[1:]
                        url = WEB + "/Web/UserRouter.aspx"
                        break
                    url = loc2
                    continue
                self.landing_url = url
                self.landing_body = html
                return {"url": url, "status": st, "len": len(html)}
        raise RuntimeError("No se pudo entrar al panel (posible cambio de flujo)")

    def api(self, path, method="GET", data=None, headers=None, follow=True):
        url = path if path.startswith("http") else API + path
        h = {
            "Accept": "application/json, text/plain, */*",
            "Origin": WEB,
            "Referer": WEB + "/",
            "x-version": "1.0",
        }
        if data is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        opener = self.op if follow else self.nore
        out = {
            "path": path,
            "method": method,
            "status": None,
            "headers": {},
            "body": "",
            "location": None,
            "error": None,
        }
        try:
            with opener.open(self._req(url, data, h), timeout=30) as r:
                out["status"] = r.status
                out["headers"] = {k.lower(): v for k, v in r.headers.items()}
                out["location"] = r.headers.get("Location")
                out["body"] = r.read(500000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            out["status"] = e.code
            out["headers"] = {k.lower(): v for k, v in e.headers.items()}
            out["location"] = e.headers.get("Location")
            try:
                out["body"] = e.read(500000).decode("utf-8", "replace")
            except Exception:
                pass
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
        return out

    def web(self, url):
        if not url.startswith("http"):
            url = WEB + url
        try:
            st, final, body = self._get_follow(url)
        except urllib.error.HTTPError as e:
            st, final = e.code, url
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:
                body = ""
        return {"status": st, "url": final, "body": body}


INST = os.environ.get("INST", "2380700064")
CAL = os.environ.get("CAL", "2026")
GROUP = os.environ.get("GROUP", "1002001131")
ALLOWED_PERIODS = {"1", "2", "3", "4"}
SUBJECT_RE = re.compile(r"^[A-Za-z0-9]{1,8}$")
WEIGHTS = {"1": 0.55, "2": 0.15, "3": 0.30}
DIMENSION_LABELS = {"1": "Actividades", "2": "Examen", "3": "Actitudinal"}
MIN_GRADE = 1.0
MAX_GRADE = 5.0
MAX_BODY = 5 * 1024 * 1024
EDIT_PASSWORD = os.environ.get("EDIT_PASSWORD") or "monda"
DOCUMENT_KEYS = (
    "numeroIdentificacion",
    "numeroDocumento",
    "numeroDocumentoIdentidad",
    "documentoIdentidad",
    "documento",
    "numDocumento",
    "identificacion",
    "identificación",
    "cedula",
    "cédula",
    "codigo",
    "idUsuario",
)

STUDENTS = {
    "1073998061": {
        "idEstudiante": "0001589389",
        "nombre": "JOSE DAVID ROJAS GARCIA",
    },
}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def load_students():
    out = {}
    for doc, info in STUDENTS.items():
        sid = str(info.get("idEstudiante") or "").strip()
        if doc and sid:
            out[str(doc).strip()] = {
                "idEstudiante": sid,
                "nombre": str(info.get("nombre") or "").strip(),
            }

    data = None
    for path in (
        os.path.join(BASE_DIR, "students.json"),
        os.path.join(os.getcwd(), "students.json"),
    ):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            break
        except FileNotFoundError:
            continue
        except Exception:
            data = None
    if isinstance(data, dict):
        for key, value in data.items():
            doc = str(key).strip()
            if not isinstance(value, dict):
                continue
            sid = str(value.get("idEstudiante") or "").strip()
            if doc and sid:
                out[doc] = {
                    "idEstudiante": sid,
                    "nombre": str(value.get("nombre") or "").strip(),
                }
    return out


def full_name(row):
    if not isinstance(row, dict):
        return ""
    name = str(row.get("nombreCompleto") or "").strip()
    if name:
        return name
    parts = [
        str(row.get("nombres") or "").strip(),
        str(row.get("apellidos") or "").strip(),
    ]
    name = " ".join(p for p in parts if p)
    if name:
        return name
    return str(row.get("nombre") or "").strip()


def normalize_document(value):
    text = str(value or "").strip()
    if not text:
        return ""
    digits = re.sub(r"\D", "", text)
    if digits:
        return digits.lstrip("0") or "0"
    return text.lower()


def documents_match(left, right):
    return normalize_document(left) == normalize_document(right)


def planilla_document(row):
    if not isinstance(row, dict):
        return ""
    for key in DOCUMENT_KEYS:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def numeric_grade(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def average(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 2) if values else None


def check_edit_password(password):
    if not isinstance(password, str):
        return False
    return hmac.compare_digest(password, EDIT_PASSWORD)


class SinaiApi:
    def __init__(self):
        user = os.environ.get("DOCB_USER")
        password = os.environ.get("DOCB_PASS")
        if not user or not password:
            raise RuntimeError("Faltan DOCB_USER y/o DOCB_PASS en el entorno.")
        self.client = SinaiClient(user, password, "docenteB")
        self.client.login()
        self.client.connect()
        self.headers = {"x-idusuario": user, "x-idinstitucion": INST}
        self.lock = threading.Lock()
        self._subjects = None
        self._subjects_at = 0.0

    def _get(self, path):
        with self.lock:
            result = self.client.api(path, headers=self.headers)
        if result["status"] != 200:
            raise ApiError(502, "La API respondió con estado %s." % result["status"])
        try:
            data = json.loads(result["body"])
        except Exception:
            raise ApiError(502, "La API devolvió una respuesta no válida.")
        return data

    def subjects(self):
        now = time.time()
        if self._subjects is not None and now - self._subjects_at < 300:
            return self._subjects
        data = self._get("/api/Asignaturas/Grupo/%s/%s" % (CAL, GROUP))
        obj = data.get("objeto") if isinstance(data, dict) else data
        if not isinstance(obj, list):
            raise ApiError(502, "Respuesta inesperada de asignaturas.")
        subjects = []
        for item in obj:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("idAsignatura") or "").strip()
            if sid:
                subjects.append({
                    "id": sid,
                    "nombre": str(item.get("asignatura") or "").strip(),
                })
        self._subjects = subjects
        self._subjects_at = now
        return subjects

    def planilla(self, subject):
        data = self._get("/api/Matricula/Planillas/%s/%s/%s?idEstado=1" % (CAL, GROUP, subject))
        obj = data.get("objeto") if isinstance(data, dict) else data
        if not isinstance(obj, list):
            raise ApiError(502, "Respuesta inesperada de la planilla.")
        return obj

    def notes(self, subject, period):
        data = self._get("/api/NotasActividadesEvaluativas/Asignatura/%s/%s/%s/%s" % (CAL, GROUP, period, subject))
        obj = data.get("objeto") if isinstance(data, dict) else data
        if not isinstance(obj, list):
            raise ApiError(502, "Respuesta inesperada de notas.")
        return obj

    def activities(self, subject, period):
        data = self._get("/api/ActividadesEvaluativas/%s/%s/%s/%s" % (CAL, GROUP, period, subject))
        obj = data.get("objeto") if isinstance(data, dict) else data
        if not isinstance(obj, list):
            raise ApiError(502, "Respuesta inesperada de actividades.")
        return obj

    def resolve_student(self, usuario, rows):
        students = load_students()
        by_sid = {
            str(row.get("idEstudiante")).strip(): row
            for row in rows
            if isinstance(row, dict) and row.get("idEstudiante")
        }

        for row in rows:
            if not isinstance(row, dict):
                continue
            sid = str(row.get("idEstudiante") or "").strip()
            if not sid:
                continue
            document = planilla_document(row)
            if (document and documents_match(usuario, document)) or documents_match(usuario, sid):
                name = full_name(row)
                if not name:
                    for key, info in students.items():
                        if info["idEstudiante"] == sid:
                            name = info["nombre"]
                            break
                return sid, name or sid

        for document, info in students.items():
            if not documents_match(usuario, document):
                continue
            sid = info["idEstudiante"]
            name = info["nombre"] or full_name(by_sid.get(sid)) or sid
            return sid, name

        raise ApiError(404, "No se encontró el estudiante. Usa el documento registrado o el código interno de la planilla.")

    def _scope(self, usuario, period, subject):
        usuario = (usuario or "").strip()
        period = (period or "").strip()
        subject = (subject or "").strip()

        if not usuario or len(usuario) > 40 or not re.match(r"^[A-Za-z0-9-]+$", usuario):
            raise ApiError(400, "Usuario inválido.")
        if period not in ALLOWED_PERIODS:
            raise ApiError(400, "Periodo inválido.")
        if not SUBJECT_RE.match(subject):
            raise ApiError(400, "Asignatura inválida.")

        subjects = self.subjects()
        subject_info = next((s for s in subjects if s["id"].upper() == subject.upper()), None)
        if not subject_info:
            raise ApiError(404, "Asignatura no válida para este grupo.")

        rows = self.planilla(subject_info["id"])
        sid, student_name = self.resolve_student(usuario, rows)
        return subject_info, sid, student_name

    def _build_view(self, subject_info, period, sid, student_name, activities_list, notes_list):
        activities = sorted(
            [
                item for item in activities_list
                if isinstance(item, dict) and item.get("id") is not None
            ],
            key=lambda x: (x.get("numero") or 9999, x.get("id") or 0),
        )

        target_notes = [
            item for item in notes_list
            if isinstance(item, dict) and str(item.get("idEstudiante")).strip() == sid
        ]
        notes_by_activity = {}
        for item in target_notes:
            try:
                aid = int(item.get("idActividad"))
            except (TypeError, ValueError):
                continue
            notes_by_activity.setdefault(aid, []).append(item)

        records = []
        for activity in activities:
            aid = int(activity.get("id"))
            candidates = notes_by_activity.get(aid, [])
            with_grade = [
                item for item in candidates
                if numeric_grade(item.get("calificacion")) is not None
            ]
            selected = with_grade[-1] if with_grade else (candidates[-1] if candidates else None)
            actual = numeric_grade(selected.get("calificacion")) if selected else None
            missing = actual is None
            value = actual if actual is not None else 1.0

            name = str(
                (selected.get("nombreActividad") if selected else None)
                or activity.get("nombre")
                or ""
            ).strip()
            dimension = str(
                (selected.get("idDimension") if selected else None)
                or activity.get("idDimension")
                or ""
            ).strip()
            lower_name = name.lower()
            if dimension == "2" or "examen" in lower_name or "acumulativa" in lower_name:
                kind = "Examen"
            elif dimension == "3":
                kind = "Actitudinal"
            else:
                kind = "Actividad"

            records.append({
                "idActividad": aid,
                "numeroActividad": (
                    selected.get("numeroActividad") if selected and selected.get("numeroActividad") is not None
                    else activity.get("numero")
                ),
                "nombreActividad": name or ("Actividad %s" % (activity.get("numero") or aid)),
                "idDimension": dimension,
                "tipo": kind,
                "calificacion": value,
                "sinRegistro": missing,
                "desempeno": selected.get("desempeño") if selected else None,
                "pesoActividad": (
                    selected.get("pesoActividad") if selected else activity.get("pesoActividad")
                ),
            })

        components = {}
        for dimension, weight in WEIGHTS.items():
            values = [r["calificacion"] for r in records if r["idDimension"] == dimension]
            components[dimension] = {
                "peso": round(weight * 100),
                "promedio": average(values),
                "total": len(values),
                "etiqueta": DIMENSION_LABELS[dimension],
            }

        available = [
            (dimension, component["promedio"])
            for dimension, component in components.items()
            if component["promedio"] is not None
        ]
        if available:
            total_weight = sum(WEIGHTS[dimension] for dimension, _ in available)
            final = sum(WEIGHTS[dimension] * value for dimension, value in available) / total_weight
            final = round(final, 2)
        else:
            final = None

        component_view = {
            "actividades": components["1"],
            "examen": components["2"],
            "actitudinal": components["3"],
        }

        return {
            "usuario": "",
            "estudiante": student_name,
            "asignatura": subject_info,
            "periodo": period,
            "registros": records,
            "componentes": component_view,
            "notaFinal": final,
            "promedio": final,
            "total": len(records),
            "conNota": sum(1 for r in records if not r["sinRegistro"]),
        }

    def grades_for(self, usuario, period, subject):
        subject_info, sid, student_name = self._scope(usuario, period, subject)
        activities_list = self.activities(subject_info["id"], period)
        notes_list = self.notes(subject_info["id"], period)
        view = self._build_view(subject_info, period, sid, student_name, activities_list, notes_list)
        view["usuario"] = (usuario or "").strip()
        return view

    def _write_ok(self, result):
        if result.get("status") != 200:
            return False
        try:
            data = json.loads(result.get("body") or "{}")
        except Exception:
            return False
        return bool(data.get("isSuccess"))

    def _write(self, path, body):
        anon = SinaiClient("anon", "anon", "anon")
        headers = dict(self.headers)
        headers["Content-Type"] = "application/json"
        result = anon.api(path, method="POST", data=body, headers=headers, follow=False)
        if self._write_ok(result):
            return

        with self.lock:
            csrf = self.client.api("/auth/csrf")
            token = None
            try:
                token = json.loads(csrf["body"]).get("token")
            except Exception:
                pass
            session_headers = {"Content-Type": "application/json"}
            if token:
                session_headers["X-CSRF-TOKEN"] = token
            result = self.client.api(path, method="POST", data=body, headers=session_headers, follow=False)

        if not self._write_ok(result):
            raise ApiError(502, "La API rechazó el guardado de notas.")

    def update_grades(self, usuario, period, subject, cambios):
        subject_info, sid, student_name = self._scope(usuario, period, subject)
        subject = subject_info["id"]

        activities_list = [
            item for item in self.activities(subject, period)
            if isinstance(item, dict) and item.get("id") is not None
        ]
        activities = {int(item.get("id")): item for item in activities_list}

        if not isinstance(cambios, list) or not cambios:
            raise ApiError(400, "No hay cambios para guardar.")
        if len(cambios) > len(activities):
            raise ApiError(400, "Demasiados cambios para esta asignatura.")

        changes = {}
        for item in cambios:
            if not isinstance(item, dict):
                raise ApiError(400, "Cambio inválido.")
            try:
                activity_id = int(item.get("idActividad"))
            except (TypeError, ValueError):
                raise ApiError(400, "Actividad inválida.")
            if activity_id not in activities:
                raise ApiError(400, "La actividad no pertenece a esta asignatura y periodo.")
            try:
                value = float(item.get("calificacion"))
            except (TypeError, ValueError):
                raise ApiError(400, "Nota inválida.")
            if value < MIN_GRADE or value > MAX_GRADE:
                raise ApiError(400, "La nota debe estar entre 1.0 y 5.0.")
            changes[activity_id] = round(value, 2)

        notes_now = self.notes(subject, period)
        target_now = [
            item for item in notes_now
            if isinstance(item, dict) and str(item.get("idEstudiante")).strip() == sid
        ]

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_name = "before_%s_p%s_%s.json" % (
            re.sub(r"[^A-Za-z0-9_-]", "_", subject),
            re.sub(r"[^A-Za-z0-9_-]", "_", period),
            stamp,
        )
        backup_path = None
        backup_dirs = [
            os.path.join(BASE_DIR, "backups"),
            os.path.join(tempfile.gettempdir(), "sinai-backups"),
        ]
        for directory in backup_dirs:
            try:
                os.makedirs(directory, exist_ok=True)
                candidate = os.path.join(directory, backup_name)
                with open(candidate, "w", encoding="utf-8") as f:
                    json.dump({
                        "timestamp": datetime.now().isoformat(timespec="seconds"),
                        "usuario": (usuario or "").strip(),
                        "idEstudiante": sid,
                        "idAsignatura": subject,
                        "periodo": period,
                        "cambios": changes,
                        "target_records": target_now,
                        "all_records": notes_now,
                    }, f, ensure_ascii=False, indent=2, default=str)
                backup_path = candidate
                break
            except OSError:
                continue

        payload = copy.deepcopy(notes_now)
        target_payload = [
            item for item in payload
            if isinstance(item, dict) and str(item.get("idEstudiante")).strip() == sid
        ]
        by_activity = {}
        for item in target_payload:
            try:
                aid = int(item.get("idActividad"))
            except (TypeError, ValueError):
                continue
            by_activity.setdefault(aid, []).append(item)

        for activity_id, value in changes.items():
            matches = by_activity.get(activity_id, [])
            if matches:
                for item in matches:
                    item["calificacion"] = str(value)
            else:
                activity = activities[activity_id]
                payload.append({
                    "idInstitucion": INST,
                    "idCalendario": CAL,
                    "idEstudiante": sid,
                    "idGrupo": GROUP,
                    "idActividad": activity_id,
                    "numeroActividad": activity.get("numero"),
                    "calificacion": str(value),
                    "idCriterio": activity.get("idCriterio"),
                    "idDimension": activity.get("idDimension"),
                })

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        path = "/api/NotasActividadesEvaluativas/Guardar/%s/%s/%s/%s" % (
            CAL, GROUP, period, subject
        )
        self._write(path, body)

        after_notes = self.notes(subject, period)

        def non_null(records):
            out = []
            for item in records:
                if not isinstance(item, dict):
                    continue
                value = numeric_grade(item.get("calificacion"))
                if value is None:
                    continue
                try:
                    aid = int(item.get("idActividad"))
                except (TypeError, ValueError):
                    continue
                item_sid = str(item.get("idEstudiante")).strip()
                if item_sid == sid and aid in changes:
                    continue
                out.append((item_sid, aid, value))
            return sorted(out)

        before = non_null(notes_now)
        after_set = set(non_null(after_notes))
        lost = [item for item in before if item not in after_set]

        view = self._build_view(
            subject_info, period, sid, student_name, activities_list, after_notes
        )
        view["usuario"] = (usuario or "").strip()
        view["message"] = "Notas actualizadas correctamente."
        view["backup"] = backup_name if backup_path else None
        if lost:
            view["warning"] = (
                "Se detectaron %d notas con valor que no aparecen después del guardado. "
                "Revisar el backup." % len(lost)
            )
        return view


_API = None
_API_LOCK = threading.Lock()


def get_api():
    global _API
    with _API_LOCK:
        if _API is None:
            _API = SinaiApi()
    return _API


SECURITY_HEADERS = [
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'self'",
    ),
]


def send_bytes(start_response, status, body, content_type):
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
    ] + SECURITY_HEADERS
    start_response("%d %s" % (status, HTTPStatus(status).phrase), headers)
    return [body]


def json_response(start_response, status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return send_bytes(start_response, status, body, "application/json; charset=utf-8")


def read_index():
    return HTML_PAGE.encode("utf-8")


def read_json_body(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        length = 0
    if length <= 0:
        raise ApiError(400, "Cuerpo vacío.")
    if length > MAX_BODY:
        raise ApiError(413, "El cuerpo de la solicitud es demasiado grande.")

    raw = environ["wsgi.input"].read(length)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ApiError(400, "JSON inválido.")
    if not isinstance(data, dict):
        raise ApiError(400, "Solicitud inválida.")
    return data


def app(environ, start_response):
    method = (environ.get("REQUEST_METHOD") or "GET").upper()
    path = environ.get("PATH_INFO") or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    query = parse_qs(environ.get("QUERY_STRING") or "")

    try:
        if path in ("/", "/index.html"):
            return send_bytes(start_response, 200, read_index(), "text/html; charset=utf-8")

        if path == "/api/subjects":
            if method != "GET":
                return json_response(start_response, 405, {"error": "Método no permitido."})
            return json_response(start_response, 200, {"subjects": get_api().subjects()})

        if path == "/api/grades":
            if method == "GET":
                usuario = (query.get("usuario") or [""])[0]
                period = (query.get("periodo") or ["4"])[0]
                subject = (query.get("asignatura") or [""])[0]
                return json_response(start_response, 200, get_api().grades_for(usuario, period, subject))
            if method == "POST":
                data = read_json_body(environ)
                if not check_edit_password(str(data.get("password") or "")):
                    return json_response(start_response, 403, {"error": "Contraseña de edición incorrecta."})
                result = get_api().update_grades(
                    str(data.get("usuario") or "").strip(),
                    str(data.get("periodo") or "4").strip(),
                    str(data.get("asignatura") or "").strip(),
                    data.get("cambios"),
                )
                return json_response(start_response, 200, result)
            return json_response(start_response, 405, {"error": "Método no permitido."})

        if path == "/api/unlock":
            if method != "POST":
                return json_response(start_response, 405, {"error": "Método no permitido."})
            data = read_json_body(environ)
            if not check_edit_password(str(data.get("password") or "")):
                return json_response(start_response, 403, {"error": "Contraseña de edición incorrecta."})
            return json_response(start_response, 200, {"ok": True})

        return json_response(start_response, 404, {"error": "Ruta no encontrada."})
    except ApiError as e:
        return json_response(start_response, e.status, {"error": e.message})
    except RuntimeError as e:
        print("[config] %s" % e)
        return json_response(start_response, 500, {"error": "El servidor no está configurado."})
    except Exception as e:
        print("[app] %s" % e)
        return json_response(start_response, 500, {"error": "Error interno del servidor."})


application = app


class QuietRequestHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):
        return


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    try:
        get_api()
    except Exception as e:
        print("No se pudo iniciar la aplicación: %s" % e)
        print("Define DOCB_USER y DOCB_PASS en el entorno.")
        return 1

    server = make_server(
        host,
        port,
        app,
        server_class=ThreadingWSGIServer,
        handler_class=QuietRequestHandler,
    )
    print("Servidor local: http://%s:%s" % (host, port))
    print("Consulta y edición local. El navegador no recibe las credenciales.")
    print("Presiona Ctrl+C para detener.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()
    return 0


HTML_PAGE = (
    '<!DOCTYPE html>\n<html lang="es">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <title>Consulta de notas | Sinaí</title>\n  <style>\n    :root {\n      --bg: #eef3f8;\n      --card: #ffffff;\n      --ink: #172033;\n      --muted: #667085;\n      --line: #d9e2ec;\n      --accent: #0f5ea8;\n      --accent-dark: #0b467d;\n      --accent-soft: #e8f1fb;\n      --ok: #146c43;\n      --error: #b42318;\n      --warn: #8a5a00;\n      --shadow: 0 18px 45px rgba(23, 32, 51, 0.09);\n    }\n\n    * { box-sizing: border-box; }\n\n    body {\n      margin: 0;\n      min-height: 100vh;\n      font-family: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, Arial, sans-serif;\n      color: var(--ink);\n      background:\n        radial-gradient(circle at top left, rgba(15, 94, 168, 0.14), transparent 34rem),\n        linear-gradient(180deg, #f8fbfe 0%, var(--bg) 100%);\n    }\n\n    .shell {\n      width: min(1180px, calc(100% - 2rem));\n      margin: 0 auto;\n      padd'
    'ing: 2.5rem 0 2rem;\n    }\n\n    header.hero {\n      display: flex;\n      align-items: flex-end;\n      justify-content: space-between;\n      gap: 1rem;\n      margin-bottom: 1.4rem;\n    }\n\n    .eyebrow {\n      margin: 0 0 0.35rem;\n      color: var(--accent);\n      font-size: 0.78rem;\n      font-weight: 700;\n      letter-spacing: 0.12em;\n      text-transform: uppercase;\n    }\n\n    h1 {\n      margin: 0;\n      font-size: clamp(1.7rem, 3vw, 2.4rem);\n      letter-spacing: -0.035em;\n    }\n\n    .hero p {\n      margin: 0.55rem 0 0;\n      color: var(--muted);\n      max-width: 65ch;\n      line-height: 1.55;\n    }\n\n    .badge-readonly {\n      flex: 0 0 auto;\n      border: 1px solid #bcd3e8;\n      background: var(--accent-soft);\n      color: var(--accent-dark);\n      border-radius: 999px;\n      padding: 0.45rem 0.8rem;\n      font-size: 0.78rem;\n      font-weight: 700;\n      white-space: nowrap;\n    }\n\n    .card {\n      background: var(--card);\n      border: 1px solid var(--line);\n      border-radius:'
    ' 18px;\n      box-shadow: var(--shadow);\n    }\n\n    .search {\n      padding: 1.25rem;\n      margin-bottom: 1rem;\n    }\n\n    .search-grid {\n      display: grid;\n      grid-template-columns: minmax(190px, 1fr) 130px minmax(220px, 1.3fr) auto auto;\n      gap: 0.8rem;\n      align-items: end;\n    }\n\n    label.field {\n      display: flex;\n      flex-direction: column;\n      gap: 0.4rem;\n      font-size: 0.78rem;\n      font-weight: 700;\n      color: #344054;\n    }\n\n    input, select, button {\n      font: inherit;\n    }\n\n    input, select {\n      width: 100%;\n      min-height: 44px;\n      border: 1px solid #c7d3e0;\n      border-radius: 10px;\n      background: #fff;\n      color: var(--ink);\n      padding: 0.65rem 0.75rem;\n      outline: none;\n      transition: border-color 0.15s, box-shadow 0.15s;\n    }\n\n    input:focus, select:focus {\n      border-color: var(--accent);\n      box-shadow: 0 0 0 3px rgba(15, 94, 168, 0.14);\n    }\n\n    button {\n      min-height: 44px;\n      border: 0;\n      border-'
    'radius: 10px;\n      padding: 0.65rem 1.1rem;\n      font-weight: 700;\n      cursor: pointer;\n      transition: background 0.15s, transform 0.05s;\n    }\n\n    button:active { transform: translateY(1px); }\n\n    .primary {\n      background: var(--accent);\n      color: #fff;\n    }\n\n    .primary:hover { background: var(--accent-dark); }\n\n    .secondary {\n      background: #eef3f8;\n      color: #344054;\n      border: 1px solid #d5dfea;\n    }\n\n    .secondary:hover { background: #e2ebf5; }\n\n    button:disabled {\n      opacity: 0.62;\n      cursor: not-allowed;\n    }\n\n    .hint {\n      margin: 0.85rem 0 0;\n      color: var(--muted);\n      font-size: 0.82rem;\n      line-height: 1.45;\n    }\n\n    .status {\n      display: none;\n      margin: 0 0 1rem;\n      border-radius: 12px;\n      padding: 0.85rem 1rem;\n      font-size: 0.9rem;\n      line-height: 1.45;\n      border: 1px solid transparent;\n    }\n\n    .status.show { display: block; }\n    .status.info { background: #eef6ff; border-color: #c9def5; colo'
    'r: #174a77; }\n    .status.error { background: #fff1f0; border-color: #f5c2bd; color: var(--error); }\n    .status.success { background: #edfdf3; border-color: #b7e4c8; color: var(--ok); }\n    .status.warn { background: #fff8e6; border-color: #f0d48a; color: var(--warn); }\n\n    .hidden { display: none !important; }\n\n    .result {\n      overflow: hidden;\n    }\n\n    .result-head {\n      display: flex;\n      justify-content: space-between;\n      gap: 1rem;\n      align-items: flex-start;\n      padding: 1.2rem 1.25rem;\n      border-bottom: 1px solid var(--line);\n      background: linear-gradient(180deg, #ffffff, #fbfdff);\n    }\n\n    .student-name {\n      margin: 0;\n      font-size: 1.15rem;\n      letter-spacing: -0.015em;\n    }\n\n    .student-meta {\n      margin: 0.35rem 0 0;\n      color: var(--muted);\n      font-size: 0.84rem;\n      line-height: 1.45;\n    }\n\n    .summary {\n      display: flex;\n      flex-wrap: wrap;\n      gap: 0.55rem;\n      justify-content: flex-end;\n      max-width: 680px;\n'
    '    }\n\n    .metric {\n      min-width: 100px;\n      border: 1px solid var(--line);\n      border-radius: 12px;\n      padding: 0.55rem 0.75rem;\n      background: #fff;\n    }\n\n    .metric span {\n      display: block;\n      color: var(--muted);\n      font-size: 0.7rem;\n      font-weight: 700;\n      letter-spacing: 0.05em;\n      text-transform: uppercase;\n    }\n\n    .metric strong {\n      display: block;\n      margin-top: 0.15rem;\n      font-size: 1.15rem;\n    }\n\n    .metric.final {\n      border-color: #bcd3e8;\n      background: var(--accent-soft);\n    }\n\n    .metric.final strong { color: var(--accent-dark); }\n\n    .edit-bar {\n      display: flex;\n      justify-content: space-between;\n      align-items: center;\n      gap: 0.8rem;\n      padding: 0.85rem 1.25rem;\n      border-bottom: 1px solid var(--line);\n      background: #fbfdff;\n    }\n\n    .formula {\n      margin: 0;\n      color: var(--muted);\n      font-size: 0.78rem;\n      line-height: 1.45;\n    }\n\n    .actions {\n      display: flex;\n   '
    '   gap: 0.5rem;\n      flex-wrap: wrap;\n      justify-content: flex-end;\n    }\n\n    .unlock-panel {\n      display: flex;\n      align-items: flex-end;\n      gap: 0.65rem;\n      flex-wrap: wrap;\n      padding: 0.9rem 1.25rem;\n      border-bottom: 1px solid #f0d48a;\n      background: #fff8e6;\n    }\n\n    .unlock-panel label {\n      display: flex;\n      flex-direction: column;\n      gap: 0.35rem;\n      color: #6b4a00;\n      font-size: 0.78rem;\n      font-weight: 700;\n    }\n\n    .unlock-panel input {\n      width: min(240px, 70vw);\n      min-height: 40px;\n      border-color: #e5c46d;\n      background: #fff;\n    }\n\n    .unlock-panel input:focus {\n      border-color: var(--accent);\n      box-shadow: 0 0 0 3px rgba(15, 94, 168, 0.14);\n    }\n\n    .unlock-panel button {\n      min-height: 40px;\n    }\n\n    .table-wrap {\n      overflow-x: auto;\n    }\n\n    table {\n      width: 100%;\n      border-collapse: collapse;\n      font-size: 0.9rem;\n    }\n\n    th, td {\n      padding: 0.8rem 1rem;\n      text-alig'
    'n: left;\n      border-bottom: 1px solid #e8eef5;\n      vertical-align: top;\n    }\n\n    th {\n      background: #f7fafc;\n      color: #475467;\n      font-size: 0.72rem;\n      letter-spacing: 0.05em;\n      text-transform: uppercase;\n      white-space: nowrap;\n    }\n\n    tbody tr:hover { background: #f9fcff; }\n    tbody tr:last-child td { border-bottom: 0; }\n\n    .num {\n      color: var(--muted);\n      font-variant-numeric: tabular-nums;\n      white-space: nowrap;\n    }\n\n    .activity-name {\n      min-width: 260px;\n      line-height: 1.4;\n    }\n\n    .pill {\n      display: inline-block;\n      border-radius: 999px;\n      padding: 0.2rem 0.55rem;\n      font-size: 0.72rem;\n      font-weight: 700;\n      white-space: nowrap;\n      background: #eef3f8;\n      color: #475467;\n    }\n\n    .pill.exam {\n      background: #fff1d6;\n      color: #8a5a00;\n    }\n\n    .pill.actitudinal {\n      background: #edfdf3;\n      color: #146c43;\n    }\n\n    .grade-cell {\n      display: flex;\n      align-items: center;\n'
    '      gap: 0.45rem;\n      flex-wrap: wrap;\n      min-width: 112px;\n    }\n\n    .grade-input {\n      width: 78px;\n      min-height: 38px;\n      padding: 0.35rem 0.45rem;\n      text-align: center;\n      font-weight: 800;\n      font-variant-numeric: tabular-nums;\n      border: 1px solid transparent;\n      background: transparent;\n      border-radius: 8px;\n      color: var(--ink);\n    }\n\n    .grade-input[readonly] {\n      cursor: default;\n    }\n\n    .grade-input:focus {\n      border-color: var(--accent);\n      background: #fff;\n      box-shadow: 0 0 0 3px rgba(15, 94, 168, 0.14);\n    }\n\n    .grade-input.editing {\n      border-color: #c7d3e0;\n      background: #fff;\n    }\n\n    .missing {\n      font-size: 0.68rem;\n      font-weight: 700;\n      color: var(--warn);\n      white-space: nowrap;\n    }\n\n    .muted { color: var(--muted); }\n\n    .empty {\n      padding: 1.4rem 1.25rem;\n      color: var(--muted);\n      text-align: center;\n      border-top: 1px solid var(--line);\n    }\n\n    footer {\n    '
    '  margin-top: 1.2rem;\n      color: var(--muted);\n      font-size: 0.78rem;\n      line-height: 1.5;\n      text-align: center;\n    }\n\n    @media (max-width: 940px) {\n      .result-head { flex-direction: column; }\n      .summary { justify-content: flex-start; }\n    }\n\n    @media (max-width: 820px) {\n      .search-grid {\n        grid-template-columns: 1fr 1fr;\n      }\n      .search-grid .wide { grid-column: 1 / -1; }\n      .search-grid button { width: 100%; }\n      .edit-bar { flex-direction: column; align-items: flex-start; }\n      .actions { justify-content: flex-start; }\n      .unlock-panel { align-items: stretch; }\n      .unlock-panel input { width: 100%; max-width: none; }\n    }\n\n    @media (max-width: 520px) {\n      .shell { width: min(100% - 1rem, 1180px); padding-top: 1.3rem; }\n      .search-grid { grid-template-columns: 1fr; }\n      .search-grid .wide { grid-column: auto; }\n      header.hero { flex-direction: column; align-items: flex-start; }\n      .actions { width: 100%; }\n     '
    ' .actions button { flex: 1; }\n    }\n  </style>\n</head>\n<body>\n  <div class="shell">\n    <header class="hero">\n      <div>\n        <p class="eyebrow">Sinaí · consulta académica</p>\n        <h1>Notas del estudiante</h1>\n        <p>Ingresa el documento o el código interno del estudiante para consultar únicamente sus notas. Se muestran todas las actividades del periodo, incluidas las que aún no tienen registro.</p>\n      </div>\n      <span class="badge-readonly">Consulta y edición</span>\n    </header>\n\n    <section class="card search">\n      <form id="searchForm" autocomplete="off">\n        <div class="search-grid">\n          <label class="field wide">\n            Documento o código\n            <input id="usuario" name="usuario" type="text" inputmode="numeric" placeholder="Ej. 1073998061 u 0001589389" maxlength="40" autocomplete="off" spellcheck="false" required>\n          </label>\n          <label class="field">\n            Periodo\n            <select id="periodo" name="periodo">\n        '
    '      <option value="1">Periodo 1</option>\n              <option value="2">Periodo 2</option>\n              <option value="3">Periodo 3</option>\n              <option value="4" selected>Periodo 4</option>\n            </select>\n          </label>\n          <label class="field wide">\n            Asignatura\n            <select id="asignatura" name="asignatura" required disabled>\n              <option value="">Cargando asignaturas...</option>\n            </select>\n          </label>\n          <button id="consultar" class="primary" type="submit">Consultar</button>\n          <button id="limpiar" class="secondary" type="button">Limpiar</button>\n        </div>\n        <p class="hint">Usa el documento nacional registrado o el código interno de la planilla. La consulta es pública; para modificar notas se solicita la contraseña de edición.</p>\n      </form>\n    </section>\n\n    <div id="status" class="status" role="status" aria-live="polite"></div>\n\n    <section id="result" class="card result hidd'
    'en" aria-live="polite">\n      <div class="result-head">\n        <div>\n          <h2 id="studentName" class="student-name">—</h2>\n          <p id="studentMeta" class="student-meta">—</p>\n        </div>\n        <div class="summary">\n          <div class="metric final">\n            <span>Nota final</span>\n            <strong id="notaFinal">—</strong>\n          </div>\n          <div class="metric">\n            <span>Actividades 55%</span>\n            <strong id="compActividades">—</strong>\n          </div>\n          <div class="metric">\n            <span>Examen 15%</span>\n            <strong id="compExamen">—</strong>\n          </div>\n          <div class="metric">\n            <span>Actitudinal 30%</span>\n            <strong id="compActitudinal">—</strong>\n          </div>\n          <div class="metric">\n            <span>Actividades</span>\n            <strong id="total">0</strong>\n          </div>\n          <div class="metric">\n            <span>Con nota</span>\n            <strong id="conN'
    'ota">0</strong>\n          </div>\n        </div>\n      </div>\n\n      <div class="edit-bar">\n        <p class="formula">Nota final = 55% actividades + 15% examen + 30% actitudinal. Las actividades sin registro cuentan como 1.0. Si una dimensión no tiene actividades, su peso se redistribuye.</p>\n        <div class="actions">\n          <button id="editar" class="secondary" type="button">Editar notas</button>\n          <button id="guardar" class="primary hidden" type="button">Guardar cambios</button>\n          <button id="cancelar" class="secondary hidden" type="button">Cancelar</button>\n        </div>\n      </div>\n\n      <div id="unlockPanel" class="unlock-panel hidden">\n        <label for="editPassword">\n          Contraseña de edición\n          <input id="editPassword" type="password" autocomplete="current-password" placeholder="Contraseña">\n        </label>\n        <button id="unlockBtn" class="primary" type="button">Desbloquear</button>\n        <button id="cancelUnlock" class="secondar'
    'y" type="button">Cancelar</button>\n      </div>\n\n      <div class="table-wrap">\n        <table>\n          <thead>\n            <tr>\n              <th>#</th>\n              <th>Actividad</th>\n              <th>Dimensión</th>\n              <th>Tipo</th>\n              <th>Nota</th>\n              <th>Desempeño</th>\n            </tr>\n          </thead>\n          <tbody id="gradesBody"></tbody>\n        </table>\n      </div>\n      <div id="emptyState" class="empty hidden">No hay actividades registradas para este periodo y asignatura.</div>\n    </section>\n\n    <footer>\n      Consulta pública por documento o código interno. La edición requiere contraseña y se guarda en la API real. La sesión del docente y el arreglo completo de notas permanecen en el servidor, no en el navegador.\n    </footer>\n  </div>\n\n  <script>\n    const $ = (id) => document.getElementById(id);\n    const form = $("searchForm");\n    const usuarioInput = $("usuario");\n    const periodoSelect = $("periodo");\n    const asignaturaS'
    'elect = $("asignatura");\n    const consultarBtn = $("consultar");\n    const limpiarBtn = $("limpiar");\n    const statusBox = $("status");\n    const resultBox = $("result");\n    const editarBtn = $("editar");\n    const guardarBtn = $("guardar");\n    const cancelarBtn = $("cancelar");\n    const unlockPanel = $("unlockPanel");\n    const editPassword = $("editPassword");\n    const unlockBtn = $("unlockBtn");\n    const cancelUnlock = $("cancelUnlock");\n\n    let currentData = null;\n    let editing = false;\n    let editPasswordValue = "";\n\n    function setStatus(message, kind) {\n      statusBox.className = "status show " + (kind || "info");\n      statusBox.textContent = message;\n    }\n\n    function clearStatus() {\n      statusBox.className = "status";\n      statusBox.textContent = "";\n    }\n\n    function setLoading(loading) {\n      consultarBtn.disabled = loading;\n      consultarBtn.textContent = loading ? "Consultando..." : "Consultar";\n    }\n\n    function setEditing(next) {\n      editing = '
    'next;\n      document.querySelectorAll(".grade-input").forEach((input) => {\n        input.readOnly = !editing;\n        input.classList.toggle("editing", editing);\n      });\n      editarBtn.classList.toggle("hidden", editing);\n      guardarBtn.classList.toggle("hidden", !editing);\n      cancelarBtn.classList.toggle("hidden", !editing);\n      if (!editing) hideUnlock();\n    }\n\n    function showUnlock() {\n      unlockPanel.classList.remove("hidden");\n      editarBtn.classList.add("hidden");\n      editPassword.value = "";\n      editPassword.focus();\n    }\n\n    function hideUnlock() {\n      unlockPanel.classList.add("hidden");\n      if (!editing) editarBtn.classList.remove("hidden");\n    }\n\n    async function readApiJson(response, fallbackMessage) {\n      const text = await response.text();\n      let data;\n      try {\n        data = JSON.parse(text);\n      } catch (error) {\n        throw new Error("El servidor devolvió HTML en lugar de JSON. Abre la URL del servidor, no el archivo index.html'
    ' directamente.");\n      }\n      if (!response.ok) {\n        throw new Error(data.error || fallbackMessage);\n      }\n      return data;\n    }\n\n    function textCell(text, className) {\n      const td = document.createElement("td");\n      if (className) td.className = className;\n      td.textContent = text;\n      return td;\n    }\n\n    function gradeInput(record) {\n      const wrapper = document.createElement("div");\n      wrapper.className = "grade-cell";\n\n      const input = document.createElement("input");\n      input.type = "number";\n      input.className = "grade-input";\n      input.min = "1";\n      input.max = "5";\n      input.step = "0.01";\n      input.value = Number(record.calificacion).toFixed(2);\n      input.dataset.original = input.value;\n      input.dataset.actividad = String(record.idActividad);\n      input.readOnly = !editing;\n      input.classList.toggle("editing", editing);\n      input.setAttribute("aria-label", "Nota de " + (record.nombreActividad || "la actividad"));\n    '
    '  wrapper.appendChild(input);\n\n      if (record.sinRegistro) {\n        const note = document.createElement("span");\n        note.className = "missing";\n        note.textContent = "sin registro";\n        wrapper.appendChild(note);\n      }\n      return wrapper;\n    }\n\n    function render(data) {\n      currentData = data;\n      clearStatus();\n      resultBox.classList.remove("hidden");\n      $("studentName").textContent = data.estudiante || "Estudiante";\n      $("studentMeta").textContent = "Usuario: " + data.usuario + " · " + data.asignatura.nombre + " · Periodo " + data.periodo;\n      $("notaFinal").textContent = data.notaFinal === null ? "—" : Number(data.notaFinal).toFixed(2);\n      $("compActividades").textContent = data.componentes.actividades.promedio === null ? "—" : Number(data.componentes.actividades.promedio).toFixed(2);\n      $("compExamen").textContent = data.componentes.examen.promedio === null ? "—" : Number(data.componentes.examen.promedio).toFixed(2);\n      $("compActitud'
    'inal").textContent = data.componentes.actitudinal.promedio === null ? "—" : Number(data.componentes.actitudinal.promedio).toFixed(2);\n      $("total").textContent = String(data.total);\n      $("conNota").textContent = String(data.conNota);\n\n      const body = $("gradesBody");\n      body.textContent = "";\n      const empty = $("emptyState");\n      empty.classList.toggle("hidden", data.registros.length > 0);\n\n      for (const record of data.registros) {\n        const tr = document.createElement("tr");\n        tr.appendChild(textCell(record.numeroActividad ?? "—", "num"));\n        tr.appendChild(textCell(record.nombreActividad || "Actividad", "activity-name"));\n\n        const dimTd = document.createElement("td");\n        const dimPill = document.createElement("span");\n        dimPill.className = "pill";\n        dimPill.textContent = record.idDimension ? "Dim. " + record.idDimension : "—";\n        dimTd.appendChild(dimPill);\n        tr.appendChild(dimTd);\n\n        const typeTd = document.c'
    'reateElement("td");\n        const typePill = document.createElement("span");\n        const typeClass = record.tipo === "Examen" ? " exam" : (record.tipo === "Actitudinal" ? " actitudinal" : "");\n        typePill.className = "pill" + typeClass;\n        typePill.textContent = record.tipo || "Actividad";\n        typeTd.appendChild(typePill);\n        tr.appendChild(typeTd);\n\n        const gradeTd = document.createElement("td");\n        gradeTd.appendChild(gradeInput(record));\n        tr.appendChild(gradeTd);\n\n        const perf = record.desempeno === null || record.desempeno === undefined || record.desempeno === "" ? "—" : String(record.desempeno);\n        tr.appendChild(textCell(perf, "muted"));\n        body.appendChild(tr);\n      }\n\n      setEditing(editing);\n      if (!editing) {\n        editPasswordValue = "";\n        editPassword.value = "";\n      }\n    }\n\n    async function cargarAsignaturas() {\n      try {\n        const response = await fetch("/api/subjects", { cache: "no-store" });'
    '\n        const data = await readApiJson(response, "No se pudieron cargar las asignaturas.");\n\n        asignaturaSelect.textContent = "";\n        const placeholder = document.createElement("option");\n        placeholder.value = "";\n        placeholder.textContent = "Selecciona una asignatura";\n        asignaturaSelect.appendChild(placeholder);\n\n        for (const subject of data.subjects) {\n          const option = document.createElement("option");\n          option.value = subject.id;\n          option.textContent = subject.nombre + " (" + subject.id + ")";\n          asignaturaSelect.appendChild(option);\n        }\n\n        const preferred = data.subjects.find((s) => s.id === "3001") || data.subjects[0];\n        if (preferred) asignaturaSelect.value = preferred.id;\n        asignaturaSelect.disabled = false;\n      } catch (error) {\n        asignaturaSelect.textContent = "";\n        const option = document.createElement("option");\n        option.value = "";\n        option.textContent = "No '
    'disponible";\n        asignaturaSelect.appendChild(option);\n        asignaturaSelect.disabled = true;\n        setStatus("Error cargando asignaturas: " + error.message, "error");\n      }\n    }\n\n    form.addEventListener("submit", async (event) => {\n      event.preventDefault();\n      clearStatus();\n\n      const usuario = usuarioInput.value.trim();\n      const periodo = periodoSelect.value;\n      const asignatura = asignaturaSelect.value;\n\n      if (!usuario) {\n        setStatus("Ingresa el documento o código del estudiante.", "warn");\n        usuarioInput.focus();\n        return;\n      }\n      if (!asignatura) {\n        setStatus("Selecciona una asignatura.", "warn");\n        return;\n      }\n\n      setLoading(true);\n      try {\n        const params = new URLSearchParams({ usuario, periodo, asignatura });\n        const response = await fetch("/api/grades?" + params.toString(), { cache: "no-store" });\n        const data = await readApiJson(response, "No se pudieron consultar las notas.");\n'
    '        editing = false;\n        render(data);\n      } catch (error) {\n        resultBox.classList.add("hidden");\n        currentData = null;\n        setStatus(error.message || "Error consultando las notas.", "error");\n      } finally {\n        setLoading(false);\n      }\n    });\n\n    editarBtn.addEventListener("click", () => {\n      if (!currentData) return;\n      setEditing(false);\n      showUnlock();\n      setStatus("Ingresa la contraseña de edición para modificar las notas.", "info");\n    });\n\n    async function unlockEditing() {\n      const password = editPassword.value;\n      if (!password) {\n        setStatus("Ingresa la contraseña de edición.", "warn");\n        editPassword.focus();\n        return;\n      }\n\n      unlockBtn.disabled = true;\n      unlockBtn.textContent = "Verificando...";\n      try {\n        const response = await fetch("/api/unlock", {\n          method: "POST",\n          headers: { "Content-Type": "application/json" },\n          body: JSON.stringify({ password })'
    ',\n        });\n        await readApiJson(response, "No se pudo verificar la contraseña.");\n        editPasswordValue = password;\n        hideUnlock();\n        setEditing(true);\n        setStatus("Edición habilitada. Cambia las notas y pulsa Guardar cambios. Los cambios se guardan en la API real.", "info");\n      } catch (error) {\n        editPasswordValue = "";\n        setStatus(error.message || "Contraseña de edición incorrecta.", "error");\n        editPassword.select();\n      } finally {\n        unlockBtn.disabled = false;\n        unlockBtn.textContent = "Desbloquear";\n      }\n    }\n\n    unlockBtn.addEventListener("click", unlockEditing);\n    editPassword.addEventListener("keydown", (event) => {\n      if (event.key === "Enter") {\n        event.preventDefault();\n        unlockEditing();\n      }\n    });\n\n    cancelUnlock.addEventListener("click", () => {\n      editPasswordValue = "";\n      editPassword.value = "";\n      hideUnlock();\n      clearStatus();\n    });\n\n    cancelarBtn.addEven'
    'tListener("click", () => {\n      if (!currentData) return;\n      editPasswordValue = "";\n      editPassword.value = "";\n      setEditing(false);\n      render(currentData);\n      clearStatus();\n    });\n\n    guardarBtn.addEventListener("click", async () => {\n      if (!currentData) return;\n      if (!editPasswordValue) {\n        setEditing(false);\n        showUnlock();\n        setStatus("La edición está bloqueada. Ingresa la contraseña para guardar cambios.", "warn");\n        return;\n      }\n\n      const inputs = Array.from(document.querySelectorAll(".grade-input"));\n      const cambios = [];\n      for (const input of inputs) {\n        const raw = input.value.trim();\n        const value = raw === "" ? 1 : Number(raw);\n        if (!Number.isFinite(value) || value < 1 || value > 5) {\n          setStatus("Nota inválida. Usa un valor entre 1.0 y 5.0.", "warn");\n          input.focus();\n          return;\n        }\n        const original = Number(input.dataset.original);\n        if (Math.abs(v'
    'alue - original) > 0.0001) {\n          cambios.push({\n            idActividad: Number(input.dataset.actividad),\n            calificacion: Number(value.toFixed(2)),\n          });\n        }\n      }\n\n      if (!cambios.length) {\n        setStatus("No hay cambios para guardar.", "info");\n        return;\n      }\n\n      const confirmed = confirm("Se guardarán cambios reales en las notas de " + currentData.estudiante + ". ¿Continuar?");\n      if (!confirmed) return;\n\n      guardarBtn.disabled = true;\n      guardarBtn.textContent = "Guardando...";\n      try {\n        const response = await fetch("/api/grades", {\n          method: "POST",\n          headers: { "Content-Type": "application/json" },\n          body: JSON.stringify({\n            usuario: currentData.usuario,\n            periodo: currentData.periodo,\n            asignatura: currentData.asignatura.id,\n            password: editPasswordValue,\n            cambios,\n          }),\n        });\n        const data = await readApiJson(response'
    ', "No se pudieron guardar las notas.");\n        editPasswordValue = "";\n        editPassword.value = "";\n        editing = false;\n        render(data);\n        const backup = data.backup ? " Respaldo: " + data.backup : "";\n        if (data.warning) {\n          setStatus(data.warning + backup, "warn");\n        } else {\n          setStatus((data.message || "Notas guardadas correctamente.") + backup, "success");\n        }\n      } catch (error) {\n        setStatus(error.message || "Error guardando las notas.", "error");\n      } finally {\n        guardarBtn.disabled = false;\n        guardarBtn.textContent = "Guardar cambios";\n      }\n    });\n\n    limpiarBtn.addEventListener("click", () => {\n      resultBox.classList.add("hidden");\n      currentData = null;\n      editing = false;\n      editPasswordValue = "";\n      editPassword.value = "";\n      hideUnlock();\n      clearStatus();\n      usuarioInput.value = "";\n      usuarioInput.focus();\n    });\n\n    cargarAsignaturas();\n  </script>\n</body>\n'
    '</html>\n'
)


if __name__ == "__main__":
    sys.exit(main())
