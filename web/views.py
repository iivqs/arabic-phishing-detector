import logging
from django.shortcuts import render
from django.core.cache import cache
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from web.forms import URLForm
from detector.analyzer import analyze

RATE_LIMIT = 10       # max scans per window
RATE_WINDOW = 60      # seconds

logger = logging.getLogger(__name__)

# Arabic translations for check names — single source of truth
CHECK_NAME_AR = {
    "URL Structure":             "بنية الرابط",
    "Domain Entropy":            "عشوائية النطاق",
    "IDN Homoglyph":             "انتحال هوية بالأحرف المتشابهة",
    "Arabic Keyboard Typo":      "خطأ لوحة المفاتيح العربية",
    "Subdomain Brand Injection": "حقن العلامة التجارية",
    "Suspicious TLD":            "امتداد مشبوه",
    "Domain Lookalike":          "نطاق مشابه",
    "Domain Age":                "عمر النطاق",
    "SSL Certificate":           "شهادة SSL",
    "Content Analysis":          "تحليل المحتوى",
    "Form Exfiltration":         "تسريب بيانات النماذج",
    "Redirect Chain":            "سلسلة التحويل",
}

# Arabic translations for status values
STATUS_NAME_AR = {
    "HIGH RISK":  "خطر مرتفع",
    "SUSPICIOUS": "مشبوه",
    "CAUTION":    "تحذير",
    "PASS":       "آمن",
    "UNKNOWN":    "غير معروف",
}

CHECKS_INFO = [
    {"name": "بنية الرابط",                       "desc": "يكشف استخدام عناوين IP كنطاقات، والنطاقات الفرعية المفرطة، والكلمات المشبوهة في الرابط."},
    {"name": "عشوائية النطاق",                    "desc": "يرصد النطاقات ذات الإنتروبيا العالية التي تُولَّد آلياً — أسلوب شائع في بنية تحتية التصيد."},
    {"name": "انتحال هوية بالأحرف المتشابهة",      "desc": "يكشف نطاقات Punycode التي تستخدم أحرفاً يونيكود متطابقة بصرياً مع أحرف لاتينية لانتحال هوية العلامات التجارية."},
    {"name": "خطأ لوحة المفاتيح العربية",           "desc": "يكتشف النطاقات التي تمثل علامات تجارية سعودية مكتوبة بلوحة مفاتيح عربية عن طريق الخطأ — أسلوب تصيد يستهدف المستخدمين السعوديين."},
    {"name": "حقن العلامة التجارية",                "desc": "يكشف وضع اسم نطاق شرعي كنطاق فرعي لموقع مجهول لإيهام المستخدم بالشرعية."},
    {"name": "امتداد النطاق",  "desc": "يرصد الامتدادات الشائعة في حملات التصيد مثل .xyz و .tk و .top."},
    {"name": "نطاق مشابه",     "desc": "يكشف انتحال هوية العلامات التجارية السعودية عبر نطاقات متشابهة في الكتابة."},
    {"name": "عمر النطاق",     "desc": "يحذّر من النطاقات المسجّلة حديثاً (أقل من 30 يوماً)."},
    {"name": "شهادة SSL",      "desc": "يتحقق من وجود شهادة HTTPS صالحة وصحيحة."},
    {"name": "تحليل المحتوى",  "desc": "يرصد أسماء العلامات التجارية السعودية على نطاقات غير شرعية."},
    {"name": "سلسلة التحويل",  "desc": "يتتبع إعادة التوجيه ويكشف سلاسل التحويل المشبوهة عبر نطاقات مختلفة."},
]

SCAN_TIMEOUT = 30
MAX_HISTORY  = 5


def _get_client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def _is_rate_limited(request) -> bool:
    ip = _get_client_ip(request)
    key = f"rl:{ip}"
    count = cache.get(key, 0)
    if count >= RATE_LIMIT:
        return True
    cache.set(key, count + 1, RATE_WINDOW)
    return False


def _run_with_timeout(url: str) -> dict:
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(analyze, url)
        return future.result(timeout=SCAN_TIMEOUT)


def _translate_report(report: dict) -> dict:
    """Add Arabic name/status fields to each check result."""
    for check in report.get("checks", []):
        check["name_ar"]   = CHECK_NAME_AR.get(check["name"], check["name"])
        check["status_ar"] = STATUS_NAME_AR.get(check["status"], check["status"])
    return report


def _save_to_history(request, report: dict) -> None:
    history = request.session.get("scan_history", [])
    history.insert(0, {
        "url":        report["url"],
        "score":      report["score"],
        "risk_level": report["risk_level"],
    })
    request.session["scan_history"] = history[:MAX_HISTORY]


def index(request):
    return render(request, "web/index.html", {
        "form": URLForm(),
        "checks_info": CHECKS_INFO,
        "history": request.session.get("scan_history", []),
    })


def scan(request):
    if request.method != "POST":
        return render(request, "web/index.html", {
            "form": URLForm(),
            "checks_info": CHECKS_INFO,
            "history": request.session.get("scan_history", []),
        })

    if _is_rate_limited(request):
        return render(request, "web/error.html", {
            "form": URLForm(),
            "message": f"لقد تجاوزت الحد المسموح به ({RATE_LIMIT} طلبات في الدقيقة). يرجى الانتظار قليلاً.",
            "url": None,
        })

    form = URLForm(request.POST)
    if not form.is_valid():
        return render(request, "web/index.html", {
            "form": form,
            "checks_info": CHECKS_INFO,
            "history": request.session.get("scan_history", []),
        })

    url = form.cleaned_data["url"]

    try:
        report = _run_with_timeout(url)
    except FuturesTimeout:
        return render(request, "web/error.html", {
            "form": URLForm(),
            "message": f"انتهت مهلة الفحص ({SCAN_TIMEOUT} ثانية). قد يكون الموقع غير متاح.",
            "url": url,
        })
    except Exception:
        logger.exception("Scan failed for URL: %s", url)
        return render(request, "web/error.html", {
            "form": URLForm(),
            "message": "حدث خطأ غير متوقع أثناء الفحص. يرجى المحاولة مرة أخرى.",
            "url": url,
        })

    _translate_report(report)
    _save_to_history(request, report)
    return render(request, "web/result.html", {"report": report, "form": URLForm()})
