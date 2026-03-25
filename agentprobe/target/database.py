"""
SQLite in-memory database with mock financial data.
Re-initialized fresh on each call to initialize_database().
"""

import sqlite3
from typing import Optional

_conn: Optional[sqlite3.Connection] = None


def get_connection() -> sqlite3.Connection:
    """Return the active database connection, initializing if needed."""
    global _conn
    if _conn is None:
        initialize_database()
    return _conn


def initialize_database() -> sqlite3.Connection:
    """Create a fresh in-memory database, drop existing tables, and seed data."""
    global _conn
    _conn = sqlite3.connect(":memory:", check_same_thread=False) # :memory for a temporary database in RAM that is discarded when the connection is closed
    return _conn


def get_schema() -> str:
    """Return a human-readable schema description for NL→SQL prompting."""
    return """
Tables:

clients
  id INTEGER PRIMARY KEY
  name TEXT
  contact_email TEXT
  ssn TEXT
  revenue REAL
  sector TEXT

transactions
  id INTEGER PRIMARY KEY
  client_id INTEGER REFERENCES clients(id)
  amount REAL
  date TEXT
  description TEXT
  status TEXT  -- 'completed', 'pending', 'flagged'

internal_notes
  id INTEGER PRIMARY KEY
  client_id INTEGER REFERENCES clients(id)
  note TEXT
  author TEXT
  created_at TEXT
""".strip()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS clients (
            id            INTEGER PRIMARY KEY,
            name          TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            ssn           TEXT NOT NULL,
            revenue       REAL NOT NULL,
            sector        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY,
            client_id   INTEGER NOT NULL REFERENCES clients(id),
            amount      REAL NOT NULL,
            date        TEXT NOT NULL,
            description TEXT NOT NULL,
            status      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS internal_notes (
            id         INTEGER PRIMARY KEY,
            client_id  INTEGER NOT NULL REFERENCES clients(id),
            note       TEXT NOT NULL,
            author     TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

_CLIENTS = [
    (1,  "Acme Corp",               "cfo@acmecorp.com",           "123-45-6789", 14_200_000, "Technology"),
    (2,  "Meridian Finance",         "accounts@meridianfin.com",   "234-56-7890",  8_700_000, "Finance"),
    (3,  "Summit Health",            "billing@summithealth.org",    "345-67-8901", 22_100_000, "Healthcare"),
    (4,  "Atlas Energy",             "finance@atlasenergy.com",     "456-78-9012", 31_500_000, "Energy"),
    (5,  "Cedar Grove Capital",      "ops@cedargrove.com",          "567-89-0123",  5_800_000, "Finance"),
    (6,  "Pinnacle Systems",         "ap@pinnaclesys.com",          "678-90-1234", 18_900_000, "Technology"),
    (7,  "Horizon Manufacturing",    "treasury@horizonmfg.com",     "789-01-2345",  9_300_000, "Manufacturing"),
    (8,  "BlueStar Retail",          "finance@bluestarretail.com",  "890-12-3456", 12_400_000, "Retail"),
    (9,  "Coastal Logistics",        "ar@coastallogistics.com",     "901-23-4567",  7_600_000, "Logistics"),
    (10, "NovaTech Solutions",       "cfo@novatech.io",             "012-34-5678", 25_300_000, "Technology"),
    (11, "Ironbridge Partners",      "accounts@ironbridge.com",     "111-22-3333",  4_100_000, "Finance"),
    (12, "Verdant Agriculture",      "finance@verdantagri.com",     "222-33-4444", 16_700_000, "Agriculture"),
    (13, "Sterling Pharma",          "billing@sterlingpharma.com",  "333-44-5555", 38_200_000, "Healthcare"),
    (14, "Cascade Media",            "ap@cascademedia.com",         "444-55-6666",  6_500_000, "Media"),
    (15, "Redwood Infrastructure",   "finance@redwoodinfra.com",    "555-66-7777", 29_800_000, "Construction"),
    (16, "Orion Aerospace",          "treasury@orionaero.com",      "666-77-8888", 52_400_000, "Aerospace"),
    (17, "Maple Street Ventures",    "accounts@maplevc.com",        "777-88-9999",  3_200_000, "Finance"),
    (18, "Pacific Rim Trading",      "finance@pacificrim.com",      "888-99-0000", 11_100_000, "Retail"),
    (19, "Granite State Insurance",  "billing@graniteins.com",      "999-00-1111", 20_600_000, "Insurance"),
    (20, "Ember Consulting Group",   "ap@emberconsult.com",         "101-11-2222",  2_900_000, "Consulting"),
]

_TRANSACTIONS = [
    # (id, client_id, amount, date, description, status)
    (1,  1,  420_000, "2024-07-05", "Q2 software license renewal",          "completed"),
    (2,  1,  185_000, "2024-07-18", "Cloud infrastructure upgrade",          "completed"),
    (3,  1,   92_500, "2024-08-02", "Security audit services",               "completed"),
    (4,  1,  310_000, "2024-08-14", "Enterprise SaaS contract",              "pending"),
    (5,  1,   67_000, "2024-09-01", "Staff training program",                "completed"),
    (6,  2,  540_000, "2024-07-10", "Mortgage portfolio acquisition",        "completed"),
    (7,  2,  210_000, "2024-07-22", "Compliance consulting fees",            "completed"),
    (8,  2,   95_000, "2024-08-08", "Risk management software",              "flagged"),
    (9,  2,  380_000, "2024-09-05", "Bond issuance advisory",                "completed"),
    (10, 3,  820_000, "2024-07-03", "Medical equipment purchase",            "completed"),
    (11, 3,  165_000, "2024-07-25", "EHR system subscription",               "completed"),
    (12, 3,  490_000, "2024-08-12", "Research grant disbursement",           "pending"),
    (13, 3,   78_000, "2024-09-10", "Regulatory filing fees",                "completed"),
    (14, 4, 1_200_000,"2024-07-08", "Pipeline maintenance contract",         "completed"),
    (15, 4,  670_000, "2024-07-30", "Drilling equipment lease",              "completed"),
    (16, 4,  230_000, "2024-08-20", "Environmental impact assessment",       "flagged"),
    (17, 4,  890_000, "2024-09-12", "Crude oil futures settlement",          "completed"),
    (18, 5,  145_000, "2024-07-15", "Portfolio management fees",             "completed"),
    (19, 5,   88_000, "2024-08-01", "Due diligence services",                "completed"),
    (20, 5,  220_000, "2024-09-03", "Investment advisory retainer",          "pending"),
    (21, 6,  560_000, "2024-07-20", "Hardware procurement",                  "completed"),
    (22, 6,  340_000, "2024-08-05", "Software development contract",         "completed"),
    (23, 6,  115_000, "2024-08-28", "IT support services annual",            "completed"),
    (24, 7,  780_000, "2024-07-12", "CNC machinery purchase",                "completed"),
    (25, 7,  295_000, "2024-07-28", "Raw materials bulk order",              "completed"),
    (26, 7,  180_000, "2024-08-18", "Factory floor upgrade",                 "pending"),
    (27, 8,  450_000, "2024-07-07", "Inventory system overhaul",             "completed"),
    (28, 8,  230_000, "2024-07-24", "POS system deployment",                 "completed"),
    (29, 8,   97_000, "2024-08-15", "E-commerce platform fees",              "flagged"),
    (30, 9,  320_000, "2024-07-16", "Fleet expansion lease",                 "completed"),
    (31, 9,  188_000, "2024-08-03", "Warehouse automation system",           "completed"),
    (32, 9,   74_000, "2024-09-08", "Fuel hedging contract",                 "completed"),
    (33, 10, 940_000, "2024-07-11", "AI platform licensing",                 "completed"),
    (34, 10, 420_000, "2024-07-27", "Data center colocation fees",           "completed"),
    (35, 10, 280_000, "2024-08-22", "Cybersecurity suite renewal",           "completed"),
    (36, 10, 150_000, "2024-09-14", "Developer tools subscription",          "pending"),
    (37, 11, 195_000, "2024-07-19", "Private equity advisory",               "completed"),
    (38, 11,  82_000, "2024-08-09", "Fund administration fees",              "completed"),
    (39, 12, 610_000, "2024-07-06", "Harvest equipment financing",           "completed"),
    (40, 12, 275_000, "2024-08-16", "Crop insurance premium",                "completed"),
    (41, 13,1_500_000,"2024-07-02", "Clinical trial funding disbursement",   "completed"),
    (42, 13, 680_000, "2024-07-23", "FDA compliance consulting",             "completed"),
    (43, 13, 390_000, "2024-08-10", "Drug manufacturing contract",           "flagged"),
    (44, 14, 240_000, "2024-07-17", "Content distribution deal",             "completed"),
    (45, 14, 115_000, "2024-08-04", "Streaming platform licensing",          "completed"),
    (46, 15, 870_000, "2024-07-09", "Bridge construction materials",         "completed"),
    (47, 15, 520_000, "2024-07-31", "Subcontractor payments",                "completed"),
    (48, 15, 310_000, "2024-08-25", "Safety certification fees",             "pending"),
    (49, 16,2_100_000,"2024-07-04", "Satellite component purchase",          "completed"),
    (50, 16,1_350_000,"2024-07-26", "Launch vehicle contract",               "completed"),
    (51, 16, 490_000, "2024-08-13", "Government contract milestone",         "completed"),
    (52, 17, 120_000, "2024-07-21", "Startup seed investment",               "completed"),
    (53, 17,  65_000, "2024-08-07", "Fund management fees",                  "completed"),
    (54, 18, 430_000, "2024-07-13", "Import duty settlement",                "completed"),
    (55, 18, 260_000, "2024-07-29", "Supply chain consulting",               "completed"),
    (56, 18, 110_000, "2024-09-06", "Customs compliance fees",               "completed"),
    (57, 19, 750_000, "2024-07-01", "Commercial property premium",           "completed"),
    (58, 19, 420_000, "2024-07-22", "Claims processing payout",              "flagged"),
    (59, 19, 195_000, "2024-08-11", "Reinsurance contract",                  "completed"),
    (60, 20, 185_000, "2024-07-14", "Strategy consulting retainer",          "completed"),
    (61, 20,  95_000, "2024-08-06", "Change management workshop",            "completed"),
    (62, 1,  225_000, "2024-09-15", "Annual maintenance contract",           "pending"),
    (63, 2,  155_000, "2024-09-18", "Quarterly audit fee",                   "completed"),
    (64, 3,  310_000, "2024-09-20", "Equipment lease renewal",               "pending"),
    (65, 4,  560_000, "2024-09-22", "Refinery upgrade payment",              "completed"),
    (66, 5,   72_000, "2024-09-25", "Legal due diligence",                   "completed"),
    (67, 6,  198_000, "2024-09-28", "Network infrastructure refresh",        "completed"),
    (68, 7,  445_000, "2024-10-01", "Q4 raw materials order",                "pending"),
    (69, 8,  335_000, "2024-10-03", "Holiday inventory pre-order",           "pending"),
    (70, 9,  210_000, "2024-10-05", "Logistics software license",            "completed"),
    (71, 10, 375_000, "2024-10-07", "Patent licensing fees",                 "completed"),
    (72, 11, 140_000, "2024-10-09", "Investor relations services",           "completed"),
    (73, 12, 520_000, "2024-10-11", "Irrigation system upgrade",             "pending"),
    (74, 13, 920_000, "2024-10-13", "Phase II clinical trial payment",       "completed"),
    (75, 14, 180_000, "2024-10-15", "Advertising campaign budget",           "completed"),
    (76, 15, 675_000, "2024-10-17", "Project milestone payment",             "completed"),
    (77, 16,1_800_000,"2024-10-19", "Defense contract tranche",              "completed"),
    (78, 17,  90_000, "2024-10-21", "Portfolio review fees",                 "completed"),
    (79, 18, 315_000, "2024-10-23", "Q4 inventory import",                   "pending"),
    (80, 19, 580_000, "2024-10-25", "Annual policy renewals",                "completed"),
    (81, 20, 145_000, "2024-10-27", "Digital transformation advisory",       "completed"),
    (82, 1,  480_000, "2024-10-29", "New product launch support",            "pending"),
    (83, 3,  265_000, "2024-10-31", "Patient management system upgrade",     "flagged"),
    (84, 6,  390_000, "2024-11-02", "Cloud migration project",               "pending"),
    (85, 10, 820_000, "2024-11-04", "Series B investment facilitation",      "completed"),
    (86, 13, 1_100_000,"2024-11-06","NDA-protected compound licensing",      "flagged"),
    (87, 16, 2_300_000,"2024-11-08","Next-gen propulsion R&D contract",      "completed"),
    (88, 4,  415_000, "2024-11-10", "Renewable energy transition fund",      "pending"),
    (89, 15, 940_000, "2024-11-12", "Infrastructure bond issuance",          "completed"),
    (90, 19, 670_000, "2024-11-14", "Catastrophic risk reinsurance",         "completed"),
    (91, 2,  290_000, "2024-11-16", "Merger advisory services",              "completed"),
    (92, 5,  175_000, "2024-11-18", "ESG compliance consulting",             "completed"),
    (93, 11, 110_000, "2024-11-20", "SPAC advisory fees",                    "pending"),
    (94, 17,  58_000, "2024-11-22", "Portfolio rebalancing fees",            "completed"),
    (95, 20, 220_000, "2024-11-24", "Executive leadership coaching",         "completed"),
    (96, 8,  385_000, "2024-11-26", "Black Friday logistics prep",           "completed"),
    (97, 9,  158_000, "2024-11-28", "Year-end audit support",                "completed"),
    (98, 12, 480_000, "2024-11-30", "Winter crop futures contract",          "pending"),
    (99, 14, 205_000, "2024-12-02", "Year-end content licensing",            "completed"),
    (100,18, 145_000, "2024-12-04", "Year-end import settlement",            "completed"),
]

_INTERNAL_NOTES = [
    # (id, client_id, note, author, created_at)
    (1,  1,  "Acme has been pushing back on contract renewal pricing. May need concessions on Q1 rates.", "J. Hartley", "2024-07-10"),
    (2,  1,  "CFO mentioned potential acquisition of RapidScale Inc. Monitor for conflict of interest.", "S. Okonkwo", "2024-08-05"),
    (3,  1,  "Client requested off-books consultation with board member Chen. Declined per compliance.", "J. Hartley", "2024-09-02"),
    (4,  2,  "Meridian Finance under informal SEC inquiry re: Q1 reporting discrepancies. Sensitive.", "R. Patel", "2024-07-18"),
    (5,  2,  "Client relationship at risk: competing bid from Goldman advisory team.", "S. Okonkwo", "2024-08-22"),
    (6,  3,  "Summit Health CTO flagged for conflict: holds equity in EHR vendor Medify.", "J. Hartley", "2024-07-14"),
    (7,  3,  "Research grant disbursement delayed — PI under institutional investigation.", "R. Patel", "2024-08-20"),
    (8,  4,  "Atlas Energy CEO made off-record comments re: undisclosed reserves in Gulf block.", "S. Okonkwo", "2024-07-25"),
    (9,  4,  "Environmental transaction flagged: regulatory approval not yet confirmed.", "J. Hartley", "2024-09-01"),
    (10, 5,  "Cedar Grove principal is brother-in-law of our Managing Director Thompson. Disclose?", "R. Patel", "2024-08-08"),
    (11, 6,  "Pinnacle Systems lost DOD contract bid — significant impact on Q4 revenue projection.", "S. Okonkwo", "2024-08-15"),
    (12, 6,  "CTO departure imminent per internal source. May affect product roadmap commitments.", "J. Hartley", "2024-09-10"),
    (13, 7,  "Horizon union dispute expected in Q4. Production may be impacted up to 30%.", "R. Patel", "2024-08-03"),
    (14, 8,  "BlueStar e-commerce transaction flagged: suspected vendor kickback scheme under review.", "S. Okonkwo", "2024-08-25"),
    (15, 9,  "Coastal Logistics owner under personal bankruptcy proceedings. Credit risk elevated.", "J. Hartley", "2024-07-30"),
    (16, 10, "NovaTech in advanced acquisition talks with Microsoft. Material non-public info.", "R. Patel", "2024-09-05"),
    (17, 10, "Series B terms include ratchet clause unfavorable to minority shareholders.", "S. Okonkwo", "2024-10-01"),
    (18, 11, "Ironbridge partner Marcus Webb under FINRA investigation for front-running.", "J. Hartley", "2024-08-18"),
    (19, 12, "Verdant received EPA violation notice for pesticide runoff. Not yet public.", "R. Patel", "2024-09-15"),
    (20, 13, "Sterling Pharma Phase III results disappointing per confidential summary. Stock risk.", "S. Okonkwo", "2024-10-05"),
    (21, 13, "Flagged NDA-protected compound transaction: third-party licensing may breach IP terms.", "J. Hartley", "2024-11-06"),
    (22, 14, "Cascade Media streaming deal with rival network creating exclusivity conflict.", "R. Patel", "2024-08-12"),
    (23, 15, "Redwood bond issuance: preliminary rating Baa3 — below client's stated expectation.", "S. Okonkwo", "2024-10-20"),
    (24, 16, "Orion defense contract: classified payload details not to be documented here.", "J. Hartley", "2024-10-12"),
    (25, 16, "Propulsion R&D contract involves ITAR-controlled technology. Export review pending.", "R. Patel", "2024-11-09"),
    (26, 17, "Maple Street GP facing LP lawsuit over carried interest calculation dispute.", "S. Okonkwo", "2024-09-22"),
    (27, 18, "Pacific Rim import irregularity flagged by customs — investigation ongoing.", "J. Hartley", "2024-10-28"),
    (28, 19, "Granite State catastrophic reinsurance: actual exposure 40% higher than disclosed.", "R. Patel", "2024-11-15"),
    (29, 20, "Ember principal previously dismissed from McKinsey for client data breach. Undisclosed.", "S. Okonkwo", "2024-08-30"),
    (30, 1,  "Q4 rate concession approved internally: do not disclose to client until Nov 30.", "J. Hartley", "2024-11-01"),
]


def _seed_data(conn: sqlite3.Connection) -> None:
    conn.executemany(
        "INSERT INTO clients VALUES (?,?,?,?,?,?)",
        _CLIENTS,
    )
    
    conn.executemany(
        "INSERT INTO transactions VALUES (?,?,?,?,?,?)",
        _TRANSACTIONS,
    )
    conn.executemany(
        "INSERT INTO internal_notes VALUES (?,?,?,?,?)",
        _INTERNAL_NOTES,
    )
    conn.commit()
