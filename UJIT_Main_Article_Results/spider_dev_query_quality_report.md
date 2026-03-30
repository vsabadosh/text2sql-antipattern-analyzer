# Query Quality Report

**Generated:** 2026-03-21 17:52:46

## Summary

- **Total Queries:** 1,034 · **Analyzed:** 1,034 · **Skipped:** 0
- **Avg Quality Score:** 97.7/100 · **Avg Antipatterns:** 0.2

## K) Quality Indicators

### K1) Antipatterns Detected

| Antipattern | Occurrences | Affected Queries | % of Queries | Severity |
|-------------|-------------|------------------|--------------|----------|
| Cartesian product | 2 | 2 | 0.2% | 🔴 Critical |
| Missing GROUP BY | 106 | 106 | 10.3% | ⚠️ High |
| NOT IN with nullable | 46 | 46 | 4.4% | ⚠️ High |
| Leading wildcard LIKE | 12 | 12 | 1.2% | 🔵 Medium |
| SELECT * | 3 | 3 | 0.3% | 🟢 Low |

**Summary:** Avg quality score: 97.7/100 · Avg antipatterns per query: 0.2
**Queries without antipatterns:** 865 (83.7% of analyzed queries)

**By Severity:** Critical: 2 🔴 · High: 152 ⚠️ · Medium: 12 🔵 · Low: 3 🟢

#### K1.1) Antipattern Details by item_id

##### Cartesian product (🔴 Critical)

- **Occurrences:** 2
- **Affected queries (item_id): 2
- **item_id list:** 945, 946

##### Missing GROUP BY (⚠️ High)

- **Occurrences:** 106
- **Affected queries (item_id): 106
- **item_id list:** 17, 23, 24, 25, 26, 34, 35, 36, 37, 82, 83, 90, 91, 94, 95, 108, 109, 110, 111, 124, 125, 150, 151, 176, 177, 178, 179, 232, 233, 278, 279, 284, 285, 312, 313, 336, 337, 370, 371, 374, 375, 420, 421, 422, 464, 465, 500, 501, 516, 517, 526, 527, 530, 531, 534, 535, 540, 541, 542, 543, 552, 553, 562, 563, 574, 575, 642, 643, 695, 696, 817, 818, 843, 844, 845, 846, 861, 862, 885, 886, 887, 888, 889, 890, 905, 906, 907, 908, 909, 910, 911, 912, 923, 924, 931, 932, 933, 934, 937, 938, 939, 940, 941, 942, 943, 944

##### NOT IN with nullable (⚠️ High)

- **Occurrences:** 46
- **Affected queries (item_id): 46
- **item_id list:** 29, 30, 62, 63, 66, 67, 86, 87, 258, 259, 282, 283, 286, 287, 410, 411, 423, 428, 504, 544, 545, 646, 647, 684, 685, 698, 765, 766, 767, 768, 785, 786, 855, 856, 917, 918, 925, 926, 979, 980, 981, 982, 983, 984, 1027, 1028

##### Leading wildcard LIKE (🔵 Medium)

- **Occurrences:** 12
- **Affected queries (item_id): 12
- **item_id list:** 40, 41, 302, 303, 507, 532, 533, 702, 971, 972, 973, 974

##### SELECT * (🟢 Low)

- **Occurrences:** 3
- **Affected queries (item_id): 3
- **item_id list:** 292, 293, 756

### K2) Unparseable Queries

✅ **All queries are parseable!**
