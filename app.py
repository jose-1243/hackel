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
    for path in (
        os.path.join(BASE_DIR, "index.html"),
        os.path.join(os.getcwd(), "index.html"),
    ):
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            continue
    raise ApiError(500, "No existe index.html en el despliegue.")


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


if __name__ == "__main__":
    sys.exit(main())
