import unittest
from alma_sbom.data.models import Package

class TestPackage(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_constructor(self):
        p = Package()
