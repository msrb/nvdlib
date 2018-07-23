import datetime
import cpe

import typing

from collections import namedtuple
from enum import Enum
from itertools import chain
from nvdlib.utils import AttrDict


VERSION = '4.0'


class CVE(object):
    """Representation of a CVE entry from the NVD database."""

    def __init__(self, cve_id: str, affects: "AffectsNode", references: list, description: str,
                 configurations: list, impact: dict, published_date: str, last_modified_date: str):
        self.cve_id = cve_id
        self.affects = affects
        self.references = references or []
        self.description = description or ""
        self.configurations = configurations or []
        self.impact = impact
        self.published_date = published_date
        self.last_modified_date = last_modified_date
        # TODO: check for missing attributes

    def get_cpe(self, cpe_type=None, nodes=None) -> list:
        def _is_type(uri: str, t: str):
            return uri.startswith("cpe:/%s" % t)

        if nodes is None:
            nodes = self.configurations

        cpe_list = list()
        for node in nodes:
            if node.children:
                cpe_list.extend(self.get_cpe(cpe_type=cpe_type, nodes=node.children))

            cpe_list.extend([x for x in node.cpe if _is_type(x.cpe22Uri, cpe_type)])

        return cpe_list

    def get_affected_vendors(self) -> typing.List[str]:
        """Get affected vendors.

        :returns: List[str], list of affected vendors
        """
        return list(self.affects.keys())

    def get_affected_products(self, vendor: str = None) -> typing.List["ProductNode"]:
        """Get affected products.

        :returns: List[ProductNode], list of affected products
        """
        affected_products = list()

        if not vendor:
            affected_products = list(chain(*self.affects.values()))

        else:
            affected_products.extend([
                p for p in self.affects.values()
                if p.vendor == vendor
            ])

        return affected_products

    def get_affected_versions(self, filter_by: typing.Union[tuple, str]) -> typing.List[str]:
        """Get affected versions.

        :param filter_by: typing.Union[tuple, str]

            Either tuple of (vendor, product) or cpe string to uniquely identify which
            affected products should be returned.

        :returns: List[str], list of affected versions of a given product
        """
        if isinstance(filter_by, tuple):
            v_name, p_name = filter_by

        elif isinstance(filter_by, str):
            parsed_cpe = cpe.CPE(filter_by)
            v_name, = parsed_cpe.get_vendor()
            p_name, = parsed_cpe.get_product()

        else:
            raise TypeError(
                "Argument `by` expected to be {}, got {}".format(
                    typing.Union[tuple, str], type(filter_by)
                ))

        affected_versions = list()
        for product in self.affects[v_name]:
            if product.name.startswith(p_name):
                affected_versions.extend(
                    [version for version in product.version_data]
                )

        return affected_versions

    @classmethod
    def from_dict(cls, data):
        """Initialize class from cve json dictionary."""
        date_format = '%Y-%m-%dT%H:%MZ'
        published_date = datetime.datetime.strptime(data.get('publishedDate'), date_format)
        last_modified_date = datetime.datetime.strptime(data.get('lastModifiedDate'), date_format)

        cve_dict = data.get('cve', {})

        # CVE ID
        cve_id = cve_dict.get('CVE_data_meta', {}).get('ID')

        # Affects
        affects = AffectsNode.from_dict(cve_dict.get('affects', {}))

        # References
        references_data = cve_dict.get('references', {}).get('reference_data', [])
        references = [x.get('url') for x in references_data]

        # English description
        description_data = cve_dict.get('description', {}).get('description_data', [])
        description = ""
        for lang_description in description_data:
            if lang_description.get('lang') == 'en':
                description = lang_description.get('value', '')
                break

        # Impact
        impact = Impact.from_dict(data.get('impact', {}))

        # Configurations
        configurations = [ConfigurationNode.from_dict(x) for x in data.get('configurations', {}).get('nodes', [])]

        return cls(cve_id=cve_id,
                   affects=affects,
                   references=references,
                   description=description,
                   configurations=configurations,
                   impact=impact,
                   published_date=published_date,
                   last_modified_date=last_modified_date)


class AffectsNode(AttrDict):
    """AffectsNode is a dict structure of signatures {version: product}."""

    def __init__(self, **kwargs):
        """Initialize AffectsNode."""
        super(AffectsNode, self).__init__(**kwargs)

    @classmethod
    def from_dict(cls, node_dict):
        """Initialize AffectsNode from dictionary.

        :param node_dict: dict, expected NVD `affects` json schema
        """
        vendor_data = node_dict.get('vendor', {}).get('vendor_data', [])  # type: list
        vendor_dct = dict()
        for v_entry in vendor_data:
            vendor = v_entry.get('vendor_name', None)
            if vendor:
                vendor_dct[vendor] = list()
                for p_entry in v_entry.get('product', {}).get('product_data', []):
                    node = ProductNode(vendor, p_entry)
                    vendor_dct[vendor].append(node)

        return cls(**vendor_dct)


class ProductNode(namedtuple('ProductNode', ['name', 'vendor', 'version_data'])):
    """ProductNode is a class representing product.

    The product is represented by its name, vendor and list of versions.
    """

    def __new__(cls, vendor, product_dict):
        """Create ProductNode.

        :param vendor: str, product vendor
        :param product_dict: dict, expected NVD `product_data` json schema
        """

        name = product_dict.get('product_name', None)

        version_data = product_dict.get('version', {}).get('version_data', [])
        version_data = [v.get('version_value', None) for v in version_data]

        return super(ProductNode, cls).__new__(
            cls, name, vendor, version_data
        )


class ConfigurationOperators(Enum):
    OR = 1
    AND = 2

    @classmethod
    def from_string(cls, operator_str):

        if operator_str.upper() not in [x.name for x in cls]:
            raise ValueError('Unknown operator {op}'.format(op=operator_str))

        return cls.OR if operator_str.upper() == 'OR' else cls.AND


class ConfigurationNode(object):

    def __init__(self, cpe: list = None, operator=ConfigurationOperators.OR, negate=False, children: list = None):
        self._cpe = cpe or []
        self._operator = operator
        self._negate = negate or False
        self._children = children or []

    @property
    def cpe(self):
        return self._cpe

    @property
    def operator(self):
        return self._operator

    @property
    def negate(self):
        return self._negate

    @property
    def children(self):
        return self._children

    @classmethod
    def from_dict(cls, node_dict):
        kwargs = {}
        if 'cpe' in node_dict:
            kwargs['cpe'] = [CPE.from_dict(x) for x in node_dict['cpe']]
        if 'operator' in node_dict:
            kwargs['operator'] = ConfigurationOperators.from_string(node_dict['operator'])
        if 'negate' in node_dict:
            kwargs['negate'] = node_dict['negate']
        if 'children' in node_dict:
            kwargs['children'] = [ConfigurationNode.from_dict(x) for x in node_dict['children']]
        return cls(**kwargs)


class CPE(object):

    def __init__(self, vulnerable: bool, cpe22Uri: str, cpe23Uri: str, versionStartIncluding: str = None,
                 versionStartExcluding: str = None, versionEndIncluding: str = None, versionEndExcluding: str = None):
        self._vulnerable = vulnerable
        self._cpe22Uri = cpe22Uri
        self._cpe23Uri = cpe23Uri

        self._cpe_parser = cpe.CPE(cpe22Uri)

        self._versionExact = cpe.CPE(cpe22Uri).get_version()[0] or None

        self._versionStartIncluding = versionStartIncluding
        self._versionStartExcluding = versionStartExcluding
        self._versionEndIncluding = versionEndIncluding
        self._versionEndExcluding = versionEndExcluding

    def is_application(self):
        return self._cpe_parser.is_application()

    def is_hardware(self):
        return self._cpe_parser.is_hardware()

    def is_operating_system(self):
        return self._cpe_parser.is_operating_system()

    @property
    def vendor(self):
        return self._cpe_parser.get_vendor()[0]

    @property
    def product(self):
        return self._cpe_parser.get_product()[0]

    def get_version_tuple(self):
        return (
            self._versionExact,
            self._versionEndExcluding, self._versionEndIncluding,
            self._versionStartIncluding, self._versionStartExcluding
        )

    @property
    def vulnerable(self):
        return self._vulnerable

    @property
    def cpe22Uri(self):
        return self._cpe22Uri

    @property
    def cpe23Uri(self):
        return self._cpe23Uri

    @property
    def versionExact(self):
        return self._versionExact

    @property
    def versionStartIncluding(self):
        return self._versionStartIncluding

    @property
    def versionStartExcluding(self):
        return self._versionStartExcluding

    @property
    def versionEndIncluding(self):
        return self._versionEndIncluding

    @property
    def versionEndExcluding(self):
        return self._versionEndExcluding

    @classmethod
    def from_dict(cls, cpe_dict):
        return cls(**cpe_dict)

    def __eq__(self, other):
        if not isinstance(other, CPE):
            return False

        if not self.__dict__ == other.__dict__:
            return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.cpe23Uri


class Impact(object):

    def __init__(self, baseMetricV2: "BaseMetric", baseMetricV3: "BaseMetric"):
        self._baseMetricV2 = baseMetricV2 or None
        self._baseMetricV3 = baseMetricV3 or None

    @property
    def baseMetricV2(self):
        return self._baseMetricV2

    @property
    def baseMetricV3(self):
        return self._baseMetricV3

    @classmethod
    def from_dict(cls, impact_dict):
        baseMetricV2 = None
        baseMetricV3 = None
        if impact_dict.get('baseMetricV2'):
            baseMetricV2 = BaseMetric.from_dict(impact_dict.get('baseMetricV2'))
        if impact_dict.get('baseMetricV3'):
            baseMetricV3 = BaseMetric.from_dict(impact_dict.get('baseMetricV3'))
        return cls(baseMetricV2=baseMetricV2, baseMetricV3=baseMetricV3)


class BaseMetric(object):

    def __init__(self, cvss: "CVSS", severity: str, exploitabilityScore: int, impactScore: int, obtainAllPrivilege=False,
                 obtainUserPrivilege=False, obtainOtherPrivilege=False, userInteractionRequired=False):
        self._cvss = cvss
        self._severity = severity
        self._exploitabilityScore = exploitabilityScore
        self._impactScore = impactScore
        self._obtainAllPrivilege = obtainAllPrivilege
        self._obtainUserPrivilege = obtainUserPrivilege
        self._obtainOtherPrivilege = obtainOtherPrivilege
        self._userInteractionRequired = userInteractionRequired

    @property
    def severity(self):
        return self._severity

    @property
    def exploitabilityScore(self):
        return self._exploitabilityScore

    @property
    def impactScore(self):
        return self._impactScore

    @property
    def obtainAllPrivilege(self):
        return self._obtainAllPrivilege

    @property
    def obtainUserPrivilege(self):
        return self._obtainUserPrivilege

    @property
    def obtainOtherPrivilege(self):
        return self._obtainOtherPrivilege

    @property
    def userInteractionRequired(self):
        return self._userInteractionRequired

    @property
    def cvssV2(self):
        return self._cvss

    @property
    def cvssV3(self):
        return self._cvss

    @classmethod
    def from_dict(cls, metrics_dict):

        cvss_dict = metrics_dict.get('cvssV2') or metrics_dict.get('cvssV3')
        cvss = CVSS.from_dict(cvss_dict)

        return cls(cvss=cvss,
                   severity=metrics_dict.get('severity'),
                   exploitabilityScore=metrics_dict.get('exploitabilityScore'),
                   impactScore=metrics_dict.get('impactScore'),
                   obtainAllPrivilege=(str(metrics_dict.get('obtainAllPrivilege', '')).lower() == 'true'),
                   obtainUserPrivilege=(str(metrics_dict.get('obtainUserPrivilege', '')).lower() == 'true'),
                   obtainOtherPrivilege=(str(metrics_dict.get('obtainOtherPrivilege', '')).lower() == 'true'),
                   userInteractionRequired=(str(metrics_dict.get('userInteractionRequired', '')).lower() == 'true'))


class CVSS(object):

    def __init__(self, version: str, vectorString: str, accessVector: str,
                 accessComplexity: str, authentication: str, confidentialityImpact: str,
                 integrityImpact: str, availabilityImpact: str, baseScore: int):
        self._version = version
        self._vectorString = vectorString
        self._accessVector = accessVector
        self._accessComplexity = accessComplexity
        self._authentication = authentication
        self._confidentialityImpact = confidentialityImpact
        self._integrityImpact = integrityImpact
        self._availabilityImpact = availabilityImpact
        self._baseScore = baseScore

    @property
    def version(self):
        return self._version

    @property
    def vectorString(self):
        return self._vectorString

    @property
    def accessVector(self):
        return self._accessVector

    @property
    def accessComplexity(self):
        return self._accessComplexity

    @property
    def authentication(self):
        return self._authentication

    @property
    def confidentialityImpact(self):
        return self._confidentialityImpact

    @property
    def integrityImpact(self):
        return self._integrityImpact

    @property
    def availabilityImpact(self):
        return self._availabilityImpact

    @property
    def baseScore(self):
        return self._baseScore

    @classmethod
    def from_dict(cls, cvss_dict):
        return cls(version=cvss_dict.get('version'),
                   vectorString=cvss_dict.get('vectorString'),
                   accessVector=cvss_dict.get('accessVector'),
                   accessComplexity=cvss_dict.get('accessComplexity'),
                   authentication=cvss_dict.get('authentication'),
                   confidentialityImpact=cvss_dict.get('confidentialityImpact'),
                   integrityImpact=cvss_dict.get('integrityImpact'),
                   availabilityImpact=cvss_dict.get('availabilityImpact'),
                   baseScore=cvss_dict.get('baseScore'))
