import unittest
from datetime import datetime, timezone
from netbrain_auditor.audit import audit, collect
from netbrain_auditor.client import APIError

class AuditTests(unittest.TestCase):
    def test_findings(self):
        records = [
            {"id":"a","name":"LAB-A","mgmtIP":"192.0.2.1","model":"C9300","ver":"1","lDiscoveryTime":"2020-01-01T00:00:00Z"},
            {"id":"b","name":"LAB-B","mgmtIP":"192.0.2.1","model":"C9300","ver":"2"},
        ]
        inv, findings, duplicates, software = audit(records,30,{"C9300":["1"]},datetime(2026,1,1,tzinfo=timezone.utc))
        self.assertEqual([d["Discovery_Status"] for d in inv],["STALE","UNKNOWN"])
        self.assertEqual(len(duplicates),2)
        self.assertEqual([d["Status"] for d in software],["PASS","FAIL"])
        self.assertTrue(all(d["Audit_Status"]=="REVIEW" for d in inv))

    def test_pagination(self):
        class Client:
            def device_page(self,skip,limit):
                return {"devices":[{"id":str(i)} for i in range(skip,min(skip+limit,25))],"totalResultCount":25}
        rows, coverage = collect(Client(),10,lambda *args:None)
        self.assertEqual(len(rows),25)
        self.assertEqual(coverage,"COUNT_MATCHED")

    def test_repeated_page(self):
        class Client:
            def device_page(self,skip,limit):
                return {"devices":[{"id":"a"}]}
        with self.assertRaises(APIError):
            collect(Client(),10,lambda *args:None)

    def test_missing_array(self):
        class Client:
            def device_page(self,skip,limit):
                return {"statusCode":790200}
        with self.assertRaises(APIError):
            collect(Client(),10,lambda *args:None)

    def test_truncated(self):
        class Client:
            def device_page(self,skip,limit):
                return {"devices":[],"totalResultCount":25}
        with self.assertRaises(APIError):
            collect(Client(),10,lambda *args:None)
