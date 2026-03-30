# Query Quality Report

**Generated:** 2026-03-21 18:03:31

## Summary

- **Total Queries:** 1,534 · **Analyzed:** 1,534 · **Skipped:** 0
- **Avg Quality Score:** 99.2/100 · **Avg Antipatterns:** 0.1

## K) Quality Indicators

### K1) Antipatterns Detected

| Antipattern | Occurrences | Affected Queries | % of Queries | Severity |
|-------------|-------------|------------------|--------------|----------|
| Cartesian product | 1 | 1 | 0.1% | 🔴 Critical |
| Missing GROUP BY | 21 | 21 | 1.4% | ⚠️ High |
| LIMIT without ORDER BY | 6 | 6 | 0.4% | ⚠️ High |
| NOT IN with nullable | 2 | 2 | 0.1% | ⚠️ High |
| Function in WHERE | 144 | 144 | 9.4% | 🔵 Medium |
| Leading wildcard LIKE | 19 | 19 | 1.2% | 🔵 Medium |
| Correlated subquery | 2 | 2 | 0.1% | 🔵 Medium |
| Redundant DISTINCT | 6 | 6 | 0.4% | 🟢 Low |

**Summary:** Avg quality score: 99.2/100 · Avg antipatterns per query: 0.1
**Queries without antipatterns:** 1,334 (87.0% of analyzed queries)

**By Severity:** Critical: 1 🔴 · High: 29 ⚠️ · Medium: 165 🔵 · Low: 6 🟢

#### K1.1) Antipattern Details by item_id

##### Cartesian product (🔴 Critical)

- **Occurrences:** 1
- **Affected queries (item_id): 1
- **item_id list:** 647

##### Missing GROUP BY (⚠️ High)

- **Occurrences:** 21
- **Affected queries (item_id): 21
- **item_id list:** 164, 310, 447, 521, 524, 597, 729, 995, 1005, 1027, 1029, 1033, 1041, 1323, 1324, 1368, 1382, 1397, 1405, 1411, 1497

##### LIMIT without ORDER BY (⚠️ High)

- **Occurrences:** 6
- **Affected queries (item_id): 6
- **item_id list:** 350, 581, 752, 813, 1015, 1145

##### NOT IN with nullable (⚠️ High)

- **Occurrences:** 2
- **Affected queries (item_id): 2
- **item_id list:** 248, 888

##### Function in WHERE (🔵 Medium)

- **Occurrences:** 144
- **Affected queries (item_id): 144
- **item_id list:** 12, 13, 24, 25, 26, 28, 40, 48, 63, 67, 68, 69, 88, 99, 100, 101, 102, 103, 112, 120, 121, 127, 142, 145, 146, 153, 171, 180, 181, 183, 184, 189, 191, 240, 243, 247, 282, 533, 534, 537, 554, 592, 604, 627, 642, 643, 648, 653, 663, 666, 678, 682, 683, 846, 885, 900, 902, 948, 957, 964, 970, 971, 973, 974, 989, 992, 993, 1032, 1034, 1035, 1037, 1038, 1042, 1043, 1045, 1048, 1049, 1061, 1063, 1069, 1074, 1085, 1092, 1094, 1103, 1104, 1105, 1107, 1109, 1110, 1112, 1113, 1115, 1116, 1119, 1122, 1152, 1159, 1162, 1163, 1165, 1168, 1171, 1172, 1183, 1189, 1192, 1194, 1200, 1202, 1203, 1208, 1218, 1230, 1232, 1234, 1237, 1241, 1243, 1244, 1245, 1255, 1258, 1261, 1272, 1322, 1325, 1333, 1336, 1340, 1380, 1396, 1401, 1436, 1438, 1441, 1444, 1473, 1474, 1476, 1477, 1481, 1499, 1510

##### Leading wildcard LIKE (🔵 Medium)

- **Occurrences:** 19
- **Affected queries (item_id): 19
- **item_id list:** 409, 412, 422, 455, 459, 493, 530, 570, 586, 587, 707, 709, 939, 960, 990, 991, 1280, 1296, 1442

##### Correlated subquery (🔵 Medium)

- **Occurrences:** 2
- **Affected queries (item_id): 2
- **item_id list:** 731, 739

##### Redundant DISTINCT (🟢 Low)

- **Occurrences:** 6
- **Affected queries (item_id): 6
- **item_id list:** 50, 85, 721, 900, 1235, 1240

### K2) Unparseable Queries

✅ **All queries are parseable!**
