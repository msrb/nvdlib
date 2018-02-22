# nvdlib

## Basic usage

```python
from nvdlib.nvd import NVD

nvd = NVD.from_feeds([2017, 2018])
nvd.update()

for cve in nvd.cves():
    print(cve.cve_id)

cve = nvd.get_cve('CVE-2017-5641')
print(cve.impact.baseMetricV3.baseScore)
```