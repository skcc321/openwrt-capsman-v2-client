#!/usr/bin/env python3
"""Portable evidence-precision regression; no RouterOS or captures needed."""
import unittest

import verify_he40_live
import verify_he80_live


class AckEvidence(unittest.TestCase):
    def test_success_path_does_not_claim_transport_or_receipt(self):
        # This could also occur with an uninstrumented, silently failed
        # response writer: the manager poll cannot establish ACK receipt.
        log = "RX 0x6016 start port=0x0000\nRX 0x6027 poll (count=1) -> 0xE027 len=46\n"
        for verifier in (verify_he40_live, verify_he80_live):
            with self.subTest(verifier=verifier.__name__):
                message = verifier.ack_observation(log, log.index("RX 0x6016"))
                self.assertIn("ACK success path reached", message)
                self.assertIn("TLS write not instrumented", message)
                self.assertIn("RouterOS receipt unconfirmed", message)
                self.assertIn("manager 0x6027 observed", message)
                self.assertNotIn("0xE016 written", message)
                self.assertNotIn("receipt confirmed", message)

    def test_no_poll_or_rejected_start_does_not_pass(self):
        for verifier in (verify_he40_live, verify_he80_live):
            with self.subTest(verifier=verifier.__name__):
                for log in ("RX 0x6016 start port=0x0000\n",
                            "RX 0x6016 start port=0x0000\n"
                            "0x6016: AP not enabled\n"
                            "RX 0x6027 poll (count=1) -> 0xE027 len=46\n",
                            "0x6016: reject invalid channel descriptor\n"
                            "RX 0x6027 poll (count=1) -> 0xE027 len=46\n"):
                    with self.assertRaises(AssertionError):
                        verifier.ack_observation(log, 0)


if __name__ == "__main__":
    unittest.main()
