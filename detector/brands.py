"""
Known Saudi/Gulf brands and their legitimate domains.

Community-expandable: submit a PR to add more brands.
Each entry maps a brand name (used for content matching) to its canonical domain.
"""

SAUDI_BRANDS = {
    # Telecom
    "STC": "stc.com.sa",
    "Mobily": "mobily.com.sa",
    "Zain": "zain.com.sa",

    # Banking
    "Al Rajhi Bank": "alrajhibank.com.sa",
    "البنك الأهلي": "ncb.com.sa",
    "SNB": "snb.com.sa",
    "Samba": "samba.com.sa",
    "Riyad Bank": "riyadbank.com.sa",
    "Arab National Bank": "anb.com.sa",
    "Alinma Bank": "alinma.com",
    "Bank AlJazira": "baj.com.sa",
    "Saudi Fransi": "alfransi.com.sa",

    # Government / E-Services
    "Absher": "absher.com.sa",
    "Nafath": "nafath.sa",
    "Ministry of Interior": "moi.gov.sa",
    "Ministry of Labor": "mol.gov.sa",
    "Saudi Post": "splonline.com.sa",
    "SADAD": "sadad.com.sa",
    "Tawakkalna": "ta.com.sa",

    # E-Commerce / Services
    "Noon": "noon.com",
    "Jarir": "jarir.com",
    "Extra": "extra.com",
    "stc pay": "stcpay.com.sa",
}

# All legitimate second-level domains (for fast lookup)
LEGITIMATE_DOMAINS = set(SAUDI_BRANDS.values())
