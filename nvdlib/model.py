from enum import Enum
import datetime
import cpe

VERSION = '4.0'


class CVE(object):
    """Representation of a CVE entry from the NVD database."""

    def __init__(self, cve_id: str, references: list, description: str,
                 configurations: list, impact: dict, published_date: str, last_modified_date: str):
        self.cve_id = cve_id
        self.references = references or []
        self.description = description or ""
        self.configurations = configurations or []
        self.impact = impact
        self.published_date = published_date
        self.last_modified_date = last_modified_date
        # TODO: some attributes are missing

    @classmethod
    def from_dict(cls, data):
        """Initialize class from cve json dictionary."""
        date_format = '%Y-%m-%dT%H:%MZ'
        published_date = datetime.datetime.strptime(data.get('publishedDate'), date_format)
        last_modified_date = datetime.datetime.strptime(data.get('lastModifiedDate'), date_format)

        cve_dict = data.get('cve', {})

        # CVE ID
        cve_id = cve_dict.get('CVE_data_meta', {}).get('ID')

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
        configurations = [ConfigurationNode(x) for x in data.get('configurations', {}).get('nodes', [])]

        return cls(cve_id=cve_id,
                   references=references,
                   description=description,
                   configurations=configurations,
                   impact=impact,
                   published_date=published_date,
                   last_modified_date=last_modified_date)


class ConfigurationOperators(Enum):
    OR = 1
    AND = 2

    @classmethod
    def from_str(cls, operator_str):

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
            kwargs['children'] = [ConfigurationNode(x) for x in node_dict['children']]
        return cls(**kwargs)


class CPE(object):

    def __init__(self, vulnerable: bool, cpe22Uri: str, cpe23Uri: str, versionStartIncluding: str = None, versionStartExcluding: str = None,
                 versionEndIncluding: str = None, versionEndExcluding: str = None):
        self._vulnerable = vulnerable
        self._cpe22Uri = cpe22Uri
        self._cpe23Uri = cpe23Uri
        self._versionStartIncluding = versionStartIncluding
        self._versionStartExcluding = versionStartExcluding
        self._versionEndIncluding = versionEndIncluding
        self._versionEndExcluding = versionEndExcluding

    def is_application(self):
        return cpe.CPE(self.cpe22Uri).is_application()

    def is_hardware(self):
        return cpe.CPE(self.cpe22Uri).is_hardware()

    def is_operating_system(self):
        return cpe.CPE(self.cpe22Uri).is_operating_system()

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
