"""CVE database integration and management."""
import logging
import re
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """CVE entry with enriched data."""
    id: str  # CVE-YYYY-NNNNN
    description: str
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    severity: str = "UNKNOWN"
    affected_vendors: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_sources: List[str] = field(default_factory=list)
    has_metasploit_module: bool = False
    metasploit_paths: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    mitre_attack_techniques: List[str] = field(default_factory=list)


class CVEDatabase:
    """Manages CVE data and provides lookup/enrichment capabilities."""
    
    def __init__(self):
        self._cves: Dict[str, CVEEntry] = {}
        self._product_index: Dict[str, Set[str]] = {}  # product -> CVE IDs
        self._vendor_index: Dict[str, Set[str]] = {}   # vendor -> CVE IDs
        self._cwe_index: Dict[str, Set[str]] = {}      # CWE -> CVE IDs
        self._last_sync: Optional[datetime] = None
    
    async def lookup(self, cve_id: str) -> Optional[CVEEntry]:
        """Lookup a CVE by its ID."""
        cve_id = cve_id.upper().strip()
        if not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return None
        
        if cve_id in self._cves:
            return self._cves[cve_id]
        
        # Try to fetch from NVD
        return await self._fetch_from_nvd(cve_id)
    
    async def search_by_product(self, product: str, vendor: Optional[str] = None) -> List[CVEEntry]:
        """Search CVEs by affected product/vendor."""
        product_lower = product.lower()
        results = set()
        
        # Direct product match
        for prod_key, cve_ids in self._product_index.items():
            if product_lower in prod_key.lower():
                results.update(cve_ids)
        
        # Vendor filter
        if vendor:
            vendor_lower = vendor.lower()
            vendor_cves = self._vendor_index.get(vendor_lower, set())
            results &= vendor_cves
        
        return [self._cves[cid] for cid in results if cid in self._cves]
    
    async def search_by_cwe(self, cwe_id: str) -> List[CVEEntry]:
        """Search CVEs by CWE classification."""
        cve_ids = self._cwe_index.get(cwe_id.upper(), set())
        return [self._cves[cid] for cid in cve_ids if cid in self._cves]
    
    async def enrich_finding(self, finding: Dict) -> Dict:
        """Enrich a finding with CVE data if applicable."""
        title = finding.get("title", "")
        description = finding.get("description", "")
        combined = f"{title} {description}"
        
        # Extract CVE IDs
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', combined, re.IGNORECASE)
        
        enriched = {
            **finding,
            "cve_data": [],
            "exploit_available": False,
            "metasploit_available": False,
        }
        
        for cve_id in cve_ids[:5]:  # Limit to 5 CVEs per finding
            cve_data = await self.lookup(cve_id.upper())
            if cve_data:
                enriched["cve_data"].append({
                    "cve_id": cve_data.id,
                    "cvss_v3": cve_data.cvss_v3_score,
                    "severity": cve_data.severity,
                    "exploit_available": cve_data.exploit_available,
                    "metasploit": cve_data.has_metasploit_module,
                    "cwe": cve_data.cwe_ids,
                })
                if cve_data.exploit_available:
                    enriched["exploit_available"] = True
                if cve_data.has_metasploit_module:
                    enriched["metasploit_available"] = True
        
        return enriched
    
    async def get_exploitable_cves(self, min_cvss: float = 7.0) -> List[CVEEntry]:
        """Get CVEs that have known exploits available."""
        return [
            cve for cve in self._cves.values()
            if cve.exploit_available and (
                (cve.cvss_v3_score and cve.cvss_v3_score >= min_cvss) or
                (cve.cvss_v2_score and cve.cvss_v2_score >= min_cvss)
            )
        ]
    
    async def import_from_nvd(self, cve_list: List[Dict]):
        """Import CVE data from NVD JSON format."""
        for nvd_entry in cve_list:
            try:
                cve_id = nvd_entry.get("id", nvd_entry.get("cve_id", ""))
                if not cve_id:
                    continue
                
                metrics = nvd_entry.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                
                entry = CVEEntry(
                    id=cve_id.upper(),
                    description=nvd_entry.get("descriptions", [{}])[0].get("value", ""),
                    cvss_v3_score=cvss_v3.get("baseScore"),
                    cvss_v3_vector=cvss_v3.get("vectorString"),
                    severity=cvss_v3.get("baseSeverity", "UNKNOWN"),
                    affected_vendors=[c.get("vendorName", "") for c in nvd_entry.get("configurations", [])],
                    cwe_ids=[w.get("cweId", "") for w in nvd_entry.get("weaknesses", [])],
                    published_date=nvd_entry.get("published"),
                    last_modified_date=nvd_entry.get("lastModified"),
                    references=[r.get("url", "") for r in nvd_entry.get("references", [])],
                )
                
                self._add_cve(entry)
                
            except Exception as e:
                logger.warning(f"Failed to import CVE entry: {e}")
        
        self._last_sync = datetime.utcnow()
        logger.info(f"Imported {len(cve_list)} CVEs from NVD")
    
    async def _fetch_from_nvd(self, cve_id: str) -> Optional[CVEEntry]:
        """Fetch a single CVE from the NVD API."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        await self.import_from_nvd([vulns[0].get("cve", {})])
                        return self._cves.get(cve_id)
        except Exception as e:
            logger.debug(f"Failed to fetch CVE {cve_id} from NVD: {e}")
        
        return None
    
    def _add_cve(self, entry: CVEEntry):
        """Add a CVE entry to the database."""
        self._cves[entry.id] = entry
        
        # Index products
        for product in entry.affected_products:
            key = product.lower()
            if key not in self._product_index:
                self._product_index[key] = set()
            self._product_index[key].add(entry.id)
        
        # Index vendors
        for vendor in entry.affected_vendors:
            key = vendor.lower()
            if key not in self._vendor_index:
                self._vendor_index[key] = set()
            self._vendor_index[key].add(entry.id)
        
        # Index CWEs
        for cwe in entry.cwe_ids:
            if cwe not in self._cwe_index:
                self._cwe_index[cwe] = set()
            self._cwe_index[cwe].add(entry.id)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_cves": len(self._cves),
            "with_exploit": sum(1 for c in self._cves.values() if c.exploit_available),
            "with_metasploit": sum(1 for c in self._cves.values() if c.has_metasploit_module),
            "unique_vendors": len(self._vendor_index),
            "unique_products": len(self._product_index),
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
        }
