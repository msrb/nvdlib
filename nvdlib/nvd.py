import os
import requests
import hashlib
import io
import gzip
import json
import datetime

from .model import CVE

# TODO(s):
# - use sqlite(?) in background, working with raw JSON files is slow and it gets overly complicated
# - better update logic


_XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME', os.path.join(os.environ.get('HOME', '/tmp/'), '.local/share/'))
_DEFAULT_DATA_DIR = os.path.join(_XDG_DATA_HOME, 'nvd/')


class NVD(object):

    def __init__(self, data_dir=None, feed_names=None):
        self._data_dir = _DEFAULT_DATA_DIR
        if data_dir:
            self._data_dir = data_dir

        self._feeds = ()
        if feed_names:
            self._feeds = tuple(JsonFeed(x) for x in feed_names)
        else:
            this_year = datetime.datetime.now().year
            self._feeds = tuple(JsonFeed(str(x)) for x in range(2002, this_year))

    def update(self):
        """Update feeds."""
        for feed in self.feeds:
            # We don't really do updates now, we just download the latest gzip.
            feed.download()

    def get_cve(self, cve_id):
        """Return `model.CVE` for given CVE ID.

        Returns None if the CVE record was not found in currently selected feeds.
        """
        parts = cve_id.split('-')
        if len(parts) != 3:
            raise ValueError('Invalid CVE ID format: {cve_id}'.format(cve_id=cve_id))

        feed_candidates = []
        feed_name = parts[1]
        for f in self.feeds:
            if f.name == feed_name or f.name in ('recent', 'modified'):
                feed_candidates.append(f)

        for feed in feed_candidates:
            cve = feed.get_cve(cve_id)
            if cve is not None:
                return cve

    def cves(self):
        """Returns generator for iterating over all CVE entries in currently selected feeds."""
        for feed in self.feeds:
            for cve in feed.cves():
                yield cve

    @property
    def feeds(self):
        return self._feeds

    @classmethod
    def feed_exists(cls, feed_name):
        return JsonFeedMetadata(feed_name).exists()

    @classmethod
    def from_feeds(cls, feed_names, data_dir=None):
        return cls(data_dir=data_dir, feed_names=feed_names)

    @classmethod
    def from_recent(cls, data_dir=None):
        return cls(feed_names=['recent'], data_dir=data_dir)


class JsonFeed(object):

    _DATA_URL_TEMPLATE = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.json.gz'

    def __init__(self, feed_name, data_dir=None):
        self._name = feed_name

        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._data_filename = 'nvdcve-1.0-{feed}.json'.format(feed=self._name)
        self._data_path = os.path.join(self._data_dir, self._data_filename)
        self._data_url = self._DATA_URL_TEMPLATE.format(feed=self._name)

        self._metadata = JsonFeedMetadata(self._name, self._data_dir)

    @property
    def name(self):
        return self._name

    def downloaded(self):
        return os.path.exists(self._data_path) and os.path.isfile(self._data_path)

    def download(self):
        self._metadata.download()

        if self.downloaded():
            data_sha256 = self._compute_sha256()
            if data_sha256 == self._metadata.sha256:
                # already up-to-date
                return

        response = requests.get(self._data_url)
        if response.status_code != 200:
            raise IOError('Unable to download {feed} feed.'.format(feed=self._name))

        gzip_file = io.BytesIO()
        gzip_file.write(response.content)
        gzip_file.seek(0)

        json_file = gzip.GzipFile(fileobj=gzip_file, mode='rb')

        with open(self._data_path, 'wb') as f:
            f.write(json_file.read())

    def cves(self):
        # TODO: stream the json(?), cache in memory
        with open(self._data_path, 'r', encoding='utf-8') as f:
            data = json.load(f).get('CVE_Items', [])

        for cve_dict in data:
            cve = CVE.from_dict(cve_dict)
            yield cve

    def get_cve(self, cve_id):
        for cve in self.cves():
            if cve.cve_id == cve_id:
                return cve
        return None

    def _compute_sha256(self):
        sha256 = hashlib.sha256()
        with open(self._data_path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest().lower()

    def __str__(self):
        return self.name


class JsonFeedMetadata(object):

    _METADATA_URL_TEMPLATE = 'https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{feed}.meta'

    def __init__(self, feed_name, data_dir=None):
        self._name = feed_name

        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._metadata_filename = 'nvdcve-1.0-{feed}.meta'.format(feed=self._name)
        self._metadata_path = os.path.join(self._data_dir, self._metadata_filename)
        self._metadata_url = self._METADATA_URL_TEMPLATE.format(feed=self._name)

        self._last_modified = None
        self._size = None
        self._zip_size = None
        self._gz_size = None
        self._sha256 = None

        self._parsed = False

        if self.downloaded():
            with open(self._metadata_path) as f:
                data = f.read()
                self._update_metadata(self._parse_metadata(data))

    @property
    def sha256(self):
        return self._sha256.lower()

    def download(self):
        metadata = self._fetch_metadata()
        os.makedirs(self._data_dir, exist_ok=True)
        with open(self._metadata_path, 'w') as f:
            f.write(metadata)
        self._update_metadata(self._parse_metadata(metadata))

    def downloaded(self):
        return os.path.exists(self._metadata_path) and os.path.isfile(self._metadata_path)

    def exists(self):
        response = requests.head(self._metadata_url)
        if response.status_code != 200:
            return False
        return True

    def _fetch_metadata(self):
        response = requests.get(self._metadata_url)
        if response.status_code != 200:
            raise Exception('Unable to download {feed} feed.'.format(feed=self._name))
        return response.text

    # noinspection PyMethodMayBeStatic
    def _parse_metadata(self, metadata):

        metadata_dict = {
            'last_modified': None,
            'size': None,
            'zipSize': None,
            'gzSize': None,
            'sha256': None
        }

        for line in metadata.split('\n'):
            line = line.strip()
            if not line:
                # empty line, skip
                continue
            key, value = line.split(':', maxsplit=1)
            key = key.strip()
            value = value.strip()

            if key == 'lastModifiedDate':
                metadata_dict['last_modified'] = value  # TODO: datetime
            elif key == 'size':
                metadata_dict['size'] = value
            elif key == 'zipSize':
                metadata_dict['zipSize'] = value
            elif key == 'gzSize':
                metadata_dict['gzSize'] = value
            elif key == 'sha256':
                metadata_dict['sha256'] = value

        return metadata_dict

    def _update_metadata(self, metadata_dict):

        if not metadata_dict.get('sha256'):
            raise ValueError('Invalid metadata file for {feed} data feed.'.format(feed=self._name))

        metadata_dict = {'_{key}'.format(key=x): metadata_dict[x] for x in metadata_dict}
        self.__dict__.update(metadata_dict)
        self._parsed = True

    def __str__(self):
        return '[metadata:{feed}] sha256:{sha256} ({last_modified})'.format(feed=self._name,
                                                                            sha256=self._sha256,
                                                                            last_modified=self._last_modified)
