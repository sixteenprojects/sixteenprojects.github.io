"""
fetch_geodata.py
Downloads simplified world GeoJSON and enriches with ISO-2 country codes.
Output: data/geo.json (~250 KB, used by the choropleth map)
"""

import json, requests, logging
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
SOURCE_URL = "https://raw.githubusercontent.com/holtzy/D3-graph-gallery/master/DATA/world.geojson"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [GeoData] %(message)s")
log = logging.getLogger(__name__)

# Country name → ISO-2 mapping (covers all countries in victim data)
NAME_TO_ISO = {
    "Afghanistan":"AF","Albania":"AL","Algeria":"DZ","Angola":"AO","Argentina":"AR",
    "Armenia":"AM","Australia":"AU","Austria":"AT","Azerbaijan":"AZ","Bahrain":"BH",
    "Bangladesh":"BD","Belarus":"BY","Belgium":"BE","Bolivia":"BO","Bosnia and Herzegovina":"BA",
    "Botswana":"BW","Brazil":"BR","Bulgaria":"BG","Cambodia":"KH","Cameroon":"CM",
    "Canada":"CA","Chile":"CL","China":"CN","Colombia":"CO","Costa Rica":"CR",
    "Croatia":"HR","Cuba":"CU","Cyprus":"CY","Czech Rep.":"CZ","Czechia":"CZ",
    "Denmark":"DK","Dominican Rep.":"DO","Ecuador":"EC","Egypt":"EG","El Salvador":"SV",
    "Estonia":"EE","Ethiopia":"ET","Finland":"FI","France":"FR","Georgia":"GE",
    "Germany":"DE","Ghana":"GH","Greece":"GR","Guatemala":"GT","Honduras":"HN",
    "Hungary":"HU","India":"IN","Indonesia":"ID","Iran":"IR","Iraq":"IQ",
    "Ireland":"IE","Israel":"IL","Italy":"IT","Jamaica":"JM","Japan":"JP",
    "Jordan":"JO","Kazakhstan":"KZ","Kenya":"KE","Kuwait":"KW","Kyrgyzstan":"KG",
    "Latvia":"LV","Lebanon":"LB","Libya":"LY","Lithuania":"LT","Luxembourg":"LU",
    "Malaysia":"MY","Malta":"MT","Mexico":"MX","Moldova":"MD","Mongolia":"MN",
    "Montenegro":"ME","Morocco":"MA","Mozambique":"MZ","Myanmar":"MM","Nepal":"NP",
    "Netherlands":"NL","New Zealand":"NZ","Nicaragua":"NI","Nigeria":"NG",
    "North Macedonia":"MK","Norway":"NO","Oman":"OM","Pakistan":"PK","Panama":"PA",
    "Paraguay":"PY","Peru":"PE","Philippines":"PH","Poland":"PL","Portugal":"PT",
    "Qatar":"QA","Romania":"RO","Russia":"RU","Saudi Arabia":"SA","Senegal":"SN",
    "Serbia":"RS","Singapore":"SG","Slovakia":"SK","Slovenia":"SI","Somalia":"SO",
    "South Africa":"ZA","South Korea":"KR","Spain":"ES","Sri Lanka":"LK","Sudan":"SD",
    "Sweden":"SE","Switzerland":"CH","Syria":"SY","Taiwan":"TW","Tanzania":"TZ",
    "Thailand":"TH","Tunisia":"TN","Turkey":"TR","Turkmenistan":"TM","Uganda":"UG",
    "Ukraine":"UA","United Arab Emirates":"AE","United Kingdom":"GB",
    "United States of America":"US","United States":"US","Uruguay":"UY",
    "Uzbekistan":"UZ","Venezuela":"VE","Vietnam":"VN","Yemen":"YE","Zimbabwe":"ZW",
    "Hong Kong":"HK","Macau":"MO","Kosovo":"XK","Libya":"LY","Palestine":"PS",
    "Western Sahara":"EH","French Guiana":"GF","Puerto Rico":"PR","Réunion":"RE",
    "Greenland":"GL","Iceland":"IS","Cyprus":"CY","Bahamas":"BS","Barbados":"BB",
    "Trinidad and Tobago":"TT","Belize":"BZ","Haiti":"HT","Guyana":"GY","Suriname":"SR",
    "Laos":"LA","Tajikistan":"TJ","Turkmenistan":"TM","Armenia":"AM",
    "Dem. Rep. Congo":"CD","Congo":"CG","Central African Rep.":"CF","Chad":"TD",
    "Mali":"ML","Niger":"NE","Mauritania":"MR","Benin":"BJ","Togo":"TG",
    "Guinea":"GN","Sierra Leone":"SL","Liberia":"LR","Ivory Coast":"CI",
    "Burkina Faso":"BF","Guinea-Bissau":"GW","Gambia":"GM","Cabo Verde":"CV",
    "Rwanda":"RW","Burundi":"BI","Malawi":"MW","Zambia":"ZM","Angola":"AO",
    "Namibia":"NA","eSwatini":"SZ","Lesotho":"LS","Madagascar":"MG","Comoros":"KM",
    "Mauritius":"MU","Seychelles":"SC","Eritrea":"ER","Djibouti":"DJ",
    "Papua New Guinea":"PG","Timor-Leste":"TL","Solomon Islands":"SB","Fiji":"FJ",
    "Vanuatu":"VU","Samoa":"WS","Tonga":"TO","Kiribati":"KI","Micronesia":"FM",
    "Marshall Islands":"MH","Palau":"PW","Nauru":"NR","Tuvalu":"TV",
    "Korea":"KR","N. Korea":"KP","S. Korea":"KR","Kyrgyz Republic":"KG",
    "W. Sahara":"EH","Bosnia and Herz.":"BA","Eq. Guinea":"GQ",
    "S. Sudan":"SS","Falkland Is.":"FK","Fr. S. Antarctic Lands":"TF",
}


def fetch_geodata() -> dict | None:
    log.info(f"Downloading world GeoJSON (simplified, 110m)...")
    try:
        resp = requests.get(SOURCE_URL, timeout=60,
                            headers={"User-Agent": "TheSixteenProject-TIHub/1.0"})
        resp.raise_for_status()
        log.info(f"Downloaded: {len(resp.content)//1024} KB")
        return resp.json()
    except Exception as e:
        log.error(f"Failed: {e}")
        return None


def enrich(raw: dict) -> dict:
    enriched, missing = [], []
    for feat in raw.get("features", []):
        name = feat.get("properties", {}).get("name", "")
        iso = NAME_TO_ISO.get(name, "")
        if not iso:
            missing.append(name)
            continue
        feat["properties"] = {"iso": iso, "name": name}
        enriched.append(feat)
    if missing:
        log.warning(f"No ISO code for {len(missing)} countries: {missing[:10]}...")
    log.info(f"Enriched {len(enriched)} countries with ISO-2 codes")
    return {"type": "FeatureCollection", "features": enriched}


def run():
    raw = fetch_geodata()
    if not raw:
        return
    slim = enrich(raw)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = DATA_DIR / "geo.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(slim, f, ensure_ascii=False, separators=(",", ":"))
    log.info(f"Written: {out} ({out.stat().st_size//1024} KB, {len(slim['features'])} countries)")


if __name__ == "__main__":
    run()
