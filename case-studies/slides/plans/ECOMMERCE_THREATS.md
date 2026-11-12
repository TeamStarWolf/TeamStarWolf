# Slide plan: E-Commerce Threats: The Public Record, 1999 to 2026

- Study: case-studies/ECOMMERCE_THREATS.md
- Cover title: E-Commerce Threats / The Public Record / 1999 to 2026
- Subtitle: From the stolen card file to the checkout page, and who pays for it
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/ECOMMERCE_THREATS.md, told from the SEC, DOJ, ICO, FTC, court, CISA, NVD, PCI SSC, Federal Reserve and vendor record. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The loss moved from the card file to the checkout page

- **2005 to 2014:** TJX, Heartland, Target and Home Depot lost stored, processed or swiped card data.
- **From 2018:** a modified script copies what the shopper types, at BA, Ticketmaster UK and Convertr.
- **The way in was usually somebody else's key:** supplier credentials at BA and Home Depot.
- **Platforms became the mass entry point:** six Adobe Commerce and Magento entries in KEV.
- **The bill is shifting:** merchants and cardholders now carry most US debit fraud losses.
Caption: Grades: breaches, penalties, filings and KEV records Confirmed; vendor crawler counts and industry loss figures Reported.
Notes: Card-file breaches [3][5][7][8]. Browser skimming [12][13][21]. Supplier credentials [12][8], Target by press accounts [7]. KEV [23]. Who pays [95].

## KEY FACTS | Twenty-seven years of card theft in four numbers

Stat: 40M+ | card numbers in the 2008 Gonzalez charges
Stat: GBP 20m | ICO penalty on BA, down from GBP 183.39m proposed
Stat: 6 | Adobe Commerce and Magento entries in KEV
Stat: 12 days | CosmicSting fix to first attacks (Reported)
- BA's modified script ran 15 days, 21 August to 5 September 2018; the attacker was in from 22 June.
- PCI DSS 6.4.3 and 11.6.1 on payment page scripts became required on 31 March 2025.
- FIN6 carries the alias Magecart Group 6; no ATT&CK campaign covers any incident here.
Notes: Gonzalez [4]. BA penalty and dates [12]. KEV catalog 2026.11.10 [23]. CosmicSting dates are Sansec's [26]; the gap is computed. PCI DSS [63]. FIN6 [106]; campaigns [114].

## PART 1 | The record in five eras

| Era | What defined it |
|---|---|
| 1999 to 2004 | CD Universe: a stolen card file and an extortion demand |
| 2005 to 2010 | TJX, the Gonzalez ring's wireless entry, Heartland's processor |
| 2013 to 2015 | Point-of-sale malware: Target, Backoff, Home Depot |
| 2018 to 2020 | Browser skimming: BA, Ticketmaster UK, Cardbleed |
| 2022 to 2026 | Magento KEV waves, polyfill.io, the Convertr tracker |
Caption: The dot-com era study is the home for CD Universe; this study summarizes it.
Notes: CD Universe [1]. TJX [2][3]. Gonzalez [4]. Heartland [5][6]. Target [7]. Backoff [9]. Home Depot [8]. BA [12]. Ticketmaster UK [13]. Cardbleed [14]. KEV [23]. polyfill.io [15][16][17]. Convertr [21].

## PART 2 | The card-file era: stored, processed or swiped

| Case | What the primary record says |
|---|---|
| TJX, 2005 to 2007 | Intruder in from July 2005; TJX found the software itself |
| Gonzalez ring, 2008 | Wardriving into eight retailers, sniffers, ATM cash-out |
| Heartland, 2008 | Malware on the processing network; Visa and MasterCard alerted it |
| Target, 2013 | About 40 million card accounts; point-of-sale malware |
| Home Depot, 2014 | A vendor's credentials; custom self-checkout malware |
Caption: Target's HVAC contractor, BlackPOS and the ignored alerts come from press accounts (Reported).
Notes: TJX [2][3]. Gonzalez [4]. Heartland [5][6]. Target, Senate staff report [7]. Home Depot [8]. Target root-cause story Reported [7].

## PART 2 | British Airways: a supplier's key, then fifteen days of skimming

- **22 June 2018:** a Swissport employee's credentials on a Citrix gateway with no MFA.
- **26 July:** the attacker reaches plaintext logs holding about 108,000 cards.
- **21 August to 5 September:** BA's own JavaScript copies card data to an attacker domain.
- **A third party alerted BA** on 5 September; about 429,612 people potentially affected.
- **The ICO said** file-integrity monitoring already in PCI DSS would have caught the change.
Caption: The penalty fell from GBP 183.39m proposed to GBP 20m; the ICO did not identify the attacker.
Notes: All points from the ICO penalty notice of 16 October 2020 [12]. The fall of about 89 percent is computed (Inferred).

## PART 2 | Third-party code was the side door

| When | Script | What happened |
|---|---|---|
| Feb to Jun 2018 | Inbenta chat bot | Altered on Ticketmaster UK's payment page |
| Feb to Jun 2024 | polyfill.io | Domain sold, then served injected code |
| Oct 2026 | Plausible tracker | Skimmer on Convertr's checkouts for three days |
Caption: A merchant answers for code it chose to load, not only for code it wrote.
Notes: Ticketmaster UK [13]. polyfill.io: Cloudflare [15][17] Confirmed, Sansec [16] Reported. Convertr [21] Reported. The lesson is Inferred.

## PART 3 | Skimming is one class among several

Left: At the checkout
- Web skimming: own script, third-party script, or platform write.
- Card testing: small payments to validate stolen cards.
- Buy now, pay later: account takeover and stolen-card repayment.
Right: At the login and the storefront
- Credential stuffing: 1.1 million accounts at 17 companies (NY OAG).
- Scalping bots: the FTC's first BOTS Act cases, January 2021.
- Fake shops: BogusBazaar's 75,000-plus domains (Reported).
Caption: Sansec put about 64 percent of a 2022 sample server-side, where browser policies do not reach (Reported).
Notes: Skimming [12][13][26][30][35]. Card testing [48][49]. BNPL [54][55]. Credential stuffing [46]. BOTS Act [51]. BogusBazaar [56]. Server-side share [44].

## PART 4 | Magento is the commerce platform of the KEV catalog

| CVE | Name | KEV added |
|---|---|---|
| CVE-2022-24086 | Checkout input validation | 15 Feb 2022 |
| CVE-2024-34102 | CosmicSting | 17 Jul 2024 |
| CVE-2025-54236 | SessionReaper | 24 Oct 2025 |
| CVE-2026-75650 | Template injection | 8 Sep 2026 |
| CVE-2026-71362 | Incorrect authorization | 24 Sep 2026 |
| CVE-2026-48356 | PolyShell | 27 Oct 2026 |
Caption: No KEV entry for WooCommerce, PrestaShop or Shopify in catalog 2026.11.10.
Notes: KEV [23]. NVD records [24][25][27][34][33][32]. PolyShell's home study is the Magento CVE-2026-48356 lab study.

## PART 4 | Attackers moved faster than the vendor's rating

| Flaw | Vendor fix | First attacks (Sansec) |
|---|---|---|
| CosmicSting | 11 Jun 2024, low priority | 23 Jun 2024 |
| SessionReaper | 9 Sep 2025, priority 2 | 22 Oct 2025 |
| PolyShell | 14 Jul 2026, priority 2 | March 2026, before the fix |
Caption: A patch is not a cleanup: rotate the crypt key and search CMS blocks for loaders.
Notes: CosmicSting [26]. SessionReaper [27][28]. PolyShell [29][30][31]. Cleanup [26][35]. Attack dates are Reported (Sansec); the gaps are computed.

## PART 5 | Standards trailed the incidents by years

| Date | Standard or rule |
|---|---|
| Oct 2008 | PCI DSS v1.2 sets the WEP sunset for June 2010 |
| Dec 2015 | FTC order on Wyndham: 20 years of PCI DSS audits |
| Mar 2022 | PCI DSS v4.0 published |
| Dec 2023 | SEC Form 8-K Item 1.05 applies |
| Mar 2025 | 6.4.3 and 11.6.1 on payment page scripts required |
Caption: Script integrity became mandatory more than six and a half years after BA.
Notes: PCI DSS v1.2 [58]. Wyndham [10][11]. v4.0 [60]. 6.4.3 and 11.6.1 [63]. Item 1.05 [76]. The gap is Inferred from [63][12].

## PART 6 | The fraud bill is moving to merchants and cardholders

Stat: 17.6 bp | US debit fraud losses, 2023 (7.8 in 2011)
Stat: 49.9% | merchant share (38.3% in 2011)
Stat: 21.8% | cardholder share (under 1.8% in 2011)
- Card-not-present was 54.3 percent of US covered-issuer debit fraud losses in 2023.
- In-person card fraud fell from $3.68 billion to $2.91 billion, 2015 to 2016; remote rose to $4.57 billion.
- Remote card fraud was 82 percent of EEA card fraud by value in the first half of 2023.
Caption: Industry loss totals (Nilson, LexisNexis, Juniper) are Reported; the central-bank figures are Confirmed.
Notes: Federal Reserve debit data [95]. Chip displacement [96]. EBA and ECB [98]. Industry figures [82][87][89][93].

## DEFENDER VIEW | Eight moves the record supports

- Inventory, authorize and watch every script on payment pages (PCI DSS 6.4.3, 11.6.1).
- MFA on every remote path a supplier can use.
- Patch Adobe Commerce and Magento on the KEV clock, then clean up.
- Never log card data you would not want stolen.
- Treat CSP and SRI as layers, not answers.
- Defend logins and checkout against automation and card testing.
- Know who owns every third-party script; drop those that change hands.
- Rehearse disclosure: Item 1.05 runs four business days from materiality.
Notes: Scripts [63][66][12]. MFA [12][8][9]. Patching [23][26][35]. Logging [12]. CSP and SRI [104][105][44][45]. Automation [46][48]. Third-party scripts [15][16][17]. Disclosure [76][19].

## MITRE MAPPINGS | Twenty-three techniques, from supplier keys to skimmers

| Id | Technique | Tie to the record |
|---|---|---|
| T1078 | Valid Accounts | BA, Home Depot supplier credentials |
| T1133 | External Remote Services | BA's Citrix gateway |
| T1059.007 | JavaScript | FIN6, BA, Ticketmaster UK |
| T1195.002 | Compromise Software Supply Chain | Inbenta, polyfill.io, Convertr |
| T1190 | Exploit Public-Facing Application | The six Magento KEV entries |
| T1669 | Wi-Fi Networks | The Gonzalez ring's wardriving |
Caption: ATT&CK v20.0. Objects: G0037 FIN6, G0046, G0061, G0053; S0503, S0169, S0517, S0197, S0196.
Notes: Techniques [12][8][106][13][17][21][23][4] and the library data [114]. F3, CWE, CAPEC and D3FEND [114]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Suppliers are the perimeter; the browser is the new till

- **The attacker follows the data to where it is readable.**
- **Supplier credentials and supplier code** opened BA, Home Depot and Ticketmaster UK.
- **Platform monoculture concentrates risk** in one commerce platform.
- **Detection mostly comes from outside:** card brands, a third party, Europol.
- **Standards trail incidents by years.**
Caption: Overstated: "every skimmer is Magecart". Understated: re-infection, and the cardholder's rising share.
Notes: Data follows readability [3][9][12][96]. Suppliers [12][8][13]. Monoculture [23][28]. Detection [5][12][81]. Standards [58][4][63][12]. Overstated and understated [106][35][67][95].
