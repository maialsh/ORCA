import sys
import os
if not os.path.exists("/Applications/Binary Ninja.app/Contents/Resources/python"):
    print(f"Binary Ninja python API not found in expected folder")
    sys.exit(1)
sys.path.insert(0, "/Applications/Binary Ninja.app/Contents/Resources/python")
import os
import binaryninja
from binaryninja import SymbolType

class BinaryAnalysis:
    def __init__(self, file_path: str):
        """
        Initialize by loading and analyzing the binary file.
        Supported file types include ELF, shared objects, PE, DLL, etc.
        """
        self.bv = binaryninja.BinaryViewType.get_view_of_file(file_path)
        if self.bv is None:
            raise ValueError(f"Unable to load binary: {file_path}")
        # Perform analysis and wait until it's done.
        self.bv.update_analysis_and_wait()

    def extract_apis(self) -> list:
        """
        Extracts all imported APIs (function names) from the binary.
        Returns a list of API names.
        """
        # Get symbols of type ImportedFunction which typically represent imported APIs.
        imported_symbols = self.bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol)
        apis = [sym.name for sym in imported_symbols if sym.name]
        return apis


class Binary:
    def __init__(self):
        self.bin_name = None
        self.bin_path = None
        self.binary_type = None
        self.binary_instance = None
        self.import_table = None
        self.bin_apis = None
        self.export_table = None
        self.section_names = None
        self.bin_strings = None
        self.registry_keys = None
        self.bin_profile = {}
        self.error_trace = {}

    def extract_apis(self):
        analyzer = BinaryAnalysis(self.bin_path)
        apis = analyzer.extract_apis()
        self.bin_apis = apis
        
    
    def extract_strings(self, min_string_length=4):
        try:
            with open(self.bin_path, 'rb') as f:
                bin_buffer = f.read()
            raw_strings = re.findall(rb"[\x20-\x7E]{" + str(min_string_length).encode() + b",}", bin_buffer)
            strings = [s.decode("ascii", errors="ignore") for s in raw_strings]
            self.bin_strings = strings
            #self.bin_profile['strings'] = strings
        except Exception as e:
            self.error_trace['binUtils@extract_strings'] = e
            print(f"Error in extracting strings: {e}")

    def extract_xdev_mitigations(self):
        dll_chars = self.bin_instance.optional_header.dll_characteristics
        # Check for ASLR
        if dll_chars & lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE:
            self.exploit_mitigations.append("ASLR")
        # Check for Data Execution Prevention (DEP)
        if dll_chars & lief.PE.DLL_CHARACTERISTICS.NX_COMPAT:
            self.exploit_mitigations.append("DEP")
        # Check for Control Flow Guard (CFG)
        if dll_chars & lief.PE.DLL_CHARACTERISTICS.GUARD_CF:
            self.exploit_mitigations.append("CFG")
        # Check for SafeSEH (if applicable)
        if self.bin_instance.optional_header.has_safe_seh:
            self.exploit_mitigations.append("SafeSEH")
        # Check for High Entropy VA (64-bit ASLR)
        if dll_chars & lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA:
            self.exploit_mitigations.append("High Entropy VA")

    def extract_registry_keys(self):
        reg_pattern = re.compile(
            r"(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(\\[A-Za-z0-9_]+)+")
        registry_keys = []
        for s in self.bin_strings:
            match = reg_pattern.search(s)
            if match:
                registry_keys.append(match.group())
        registry_keys = list(set(registry_keys))
        self.registry_keys = registry_keys
        self.bin_profile['registry_keys'] = registry_keys

    
    def get_binary_features(self, fpath, fname):
        self.bin_path = fpath
        self.bin_name = fname
        self.fingerprint()
        self.extract_apis()
        self.bin_profile['name'] = fname
        self.bin_profile['type'] = self.binary_type
        self.bin_profile['lief-binary'] = self.bin_instance
        self.bin_profile['import_table'] = self.import_table
        self.bin_profile['export_table'] = self.export_table
        self.bin_profile['apis'] = self.bin_apis
        return self.bin_profile


    def fingerprint(self):
        try:
            bin_instance = lief.parse(self.bin_path)
            if bin_instance is None:
                return
            self.bin_instance =  bin_instance
            self.import_table = []
            self.export_table = []
            self.extract_strings()
            if isinstance(bin_instance, lief.ELF.Binary):
                self.binary_type = "ELF"
                for lib in bin_instance.libraries:
                    self.import_table.append(lib.name)
                self.section_names = [section.name for section in bin_instance.sections]
                symbols = getattr(bin_instance, "exported_functions", [])
                if symbols:
                    for sym in symbols:
                        self.export_table.append(sym)
            elif isinstance(bin_instance, lief.PE.Binary):
                self.binary_type = "PE"
                for imp in bin_instance.imports:
                    self.import_table.append(imp.name)
                self.extract_registry_keys()
                if bin_instance.has_exports:
                    for exp in bin_instance.exported_functions:
                        self.export_table.append(exp)
            elif isinstance(bin_instance, lief.MachO.Binary):
                self.binary_type = "Mach-O"
                for lib in bin_instance.imported_symbols:
                    self.import_table.append(lib.name)
                if hasattr(bin_instance, "exported_symbols"):
                    for sym in bin_instance.exported_symbols:
                        self.export_table.append(sym.name)
            else:
                 self.binary_type = "unknown"     
        except Exception as e:
            self.error_trace["binUtils@fingerprint"] = e
            print(f"Exception in binary:load_binary - {e}")
