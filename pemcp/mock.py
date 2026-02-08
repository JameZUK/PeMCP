"""Mock PE object for raw shellcode analysis mode."""


class MockPE:
    """
    A dummy wrapper to mimic a pefile.PE object for raw shellcode analysis.
    """
    def __init__(self, data):
        self.__data__ = data
        self.sections = []
        self.DOS_HEADER = None
        self.NT_HEADERS = None
        self.OPTIONAL_HEADER = None
        self.FILE_HEADER = None

        # Standard PE directories mocked as empty/None
        self.DIRECTORY_ENTRY_IMPORT = []
        self.DIRECTORY_ENTRY_EXPORT = None
        self.DIRECTORY_ENTRY_RESOURCE = None
        self.DIRECTORY_ENTRY_DEBUG = []
        self.DIRECTORY_ENTRY_TLS = None
        self.DIRECTORY_ENTRY_LOAD_CONFIG = None
        self.DIRECTORY_ENTRY_COM_DESCRIPTOR = None
        self.DIRECTORY_ENTRY_BASERELOC = []
        self.DIRECTORY_ENTRY_BOUND_IMPORT = []
        self.DIRECTORY_ENTRY_EXCEPTION = []
        self.DIRECTORY_ENTRY_DELAY_IMPORT = []
        self.RICH_HEADER = None
        self.VS_VERSIONINFO = None
        self.FileInfo = None
        self.SYMBOLS = []

    def get_warnings(self):
        return ["Loaded in Raw Shellcode Mode (PE parsing skipped)."]

    def close(self):
        pass

    def get_overlay_data_start_offset(self):
        return None

    def generate_checksum(self):
        return 0

    def get_data(self, offset=0, length=None):
        """Mimic pefile.get_data for signature extraction attempts."""
        if length is None:
            return self.__data__[offset:]
        return self.__data__[offset:offset+length]
